"""持久化模型（SQLAlchemy 2.0）。

设计取舍：
- 单文件 SQLite + WAL 即可支撑个人/小组级长期运行，换 Postgres 只改 SILVER_DB_URL。
- 证据表用哈希链（prev_hash -> chain_hash）串联，事后可验证「哪条记录被改过」。
- 资产用 normalized 唯一键做幂等 upsert，重复扫描只增信号不增重复行。

v1.0 新增的两条主线：
1. **分级而非判定**。评分只是参考，真正决定处置优先级的是 tier：
   candidate（发现即收）→ watch（有迹象，持续盯）→ confirmed（可举报）/
   dismissed（有据排除）。这条链路允许「宁可错杀」，因为错杀的成本只是存储。
2. **图是主体，表是投影**。GraphNode / GraphEdge 保留关系原始事实，
   团伙与主体归因从图上算，不从资产字段猜。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .domain import utcnow

# 分级常量集中在一处，避免散落的字符串比较
TIER_CANDIDATE = "candidate"
TIER_WATCH = "watch"
TIER_CONFIRMED = "confirmed"
TIER_DISMISSED = "dismissed"
TIER_COLD = "cold"

TIER_ORDER = [TIER_CONFIRMED, TIER_WATCH, TIER_CANDIDATE, TIER_COLD, TIER_DISMISSED]


class Base(DeclarativeBase):
    pass


class Campaign(Base):
    """同一团伙/同一套模板派生出来的一组资产。"""

    __tablename__ = "campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="active")
    summary: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    assets: Mapped[list["Asset"]] = relationship(back_populates="campaign")


class Asset(Base):
    """一个可独立研判的对象：域名、链接、APK、小程序、话术样本、收款账户。"""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, default="")
    campaign_id: Mapped[int | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True, index=True)

    score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str] = mapped_column(String(24), default="insufficient", index=True)

    # ---- v1.0 分级与发现溯源
    tier: Mapped[str] = mapped_column(String(16), default=TIER_CANDIDATE, index=True)
    discovery_source: Mapped[str] = mapped_column(String(32), default="manual", index=True)
    discovery_reason: Mapped[str] = mapped_column(Text, default="")
    # 被判定无害并降级/剔除的理由，必须写清楚，方便复核
    dismiss_reason: Mapped[str] = mapped_column(Text, default="")

    # ---- ICP 备案（unknown 表示没查到，不等于未备案）
    icp_status: Mapped[str] = mapped_column(String(24), default="unknown")
    icp_license: Mapped[str] = mapped_column(String(80), default="")
    icp_entity: Mapped[str] = mapped_column(String(200), default="")
    # 工信部违法违规名单：listed | clean | unknown。比「有无备案」更强的官方信号
    icp_violation: Mapped[str] = mapped_column(String(16), default="unknown")
    icp_violation_title: Mapped[str] = mapped_column(String(200), default="")
    icp_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    scan_count: Mapped[int] = mapped_column(Integer, default=0)
    enrich_count: Mapped[int] = mapped_column(Integer, default=0)

    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")
    reviewed_by: Mapped[str] = mapped_column(String(80), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    campaign: Mapped[Campaign | None] = relationship(back_populates="assets")
    signals: Mapped[list["SignalRow"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", order_by="SignalRow.weight.desc()"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", order_by="Evidence.id"
    )
    reports: Mapped[list["ReportDraft"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", order_by="ReportDraft.id.desc()"
    )

    __table_args__ = (
        UniqueConstraint("kind", "normalized", name="uq_asset_kind_normalized"),
        Index("ix_asset_verdict_score", "verdict", "score"),
        Index("ix_asset_tier_score", "tier", "score"),
    )


class SignalRow(Base):
    """命中信号。每次重扫先清空再写入，保证结论与当前证据一致。"""

    __tablename__ = "signals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(40), index=True)
    category: Mapped[str] = mapped_column(String(24), index=True)
    title: Mapped[str] = mapped_column(String(200))
    weight: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    detail: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(40), default="rule")
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="signals")


class Evidence(Base):
    """原始证据 + 哈希链。文件本体放 data/evidence，库里只存摘要与相对路径。"""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    chain_hash: Mapped[str] = mapped_column(String(64), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    path: Mapped[str] = mapped_column(Text, default="")
    note: Mapped[str] = mapped_column(Text, default="")
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="evidence")


class ReportDraft(Base):
    """举报材料草稿。生成不等于已提交，提交状态由人维护。"""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    channel: Mapped[str] = mapped_column(String(32), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    body: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    receipt: Mapped[str] = mapped_column(String(200), default="")

    asset: Mapped[Asset] = relationship(back_populates="reports")


class WatchTarget(Base):
    """监控目标：关键词、品牌词、已知域名、CT 规则。"""

    __tablename__ = "watch_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))          # keyword | domain | brand | cert | wallet
    value: Mapped[str] = mapped_column(String(200))
    interval_minutes: Mapped[int] = mapped_column(Integer, default=360)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(Text, default="")
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (UniqueConstraint("kind", "value", name="uq_watch_kind_value"),)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("watch_targets.id"), nullable=True, index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    trigger: Mapped[str] = mapped_column(String(24), default="manual")
    status: Mapped[str] = mapped_column(String(16), default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")


# ---------------------------------------------------------------- v1.0 新增


class DiscoveryEvent(Base):
    """发现事件：每一次「我们看见了这个东西」的原始记录。

    与 Asset 的区别：Asset 是去重后的实体，DiscoveryEvent 是流水。
    流水只追加不修改，是复盘「这个域名是怎么被发现的」的唯一依据。
    """

    __tablename__ = "discovery_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32), index=True)     # ct_stream | ct_poll | pivot | watchlist | manual
    kind: Mapped[str] = mapped_column(String(16), default="domain")
    value: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str] = mapped_column(Text, index=True)
    matched_terms: Mapped[list[str]] = mapped_column(JSON, default=list)
    score_hint: Mapped[float] = mapped_column(Float, default=0.0)
    asset_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    parent: Mapped[str] = mapped_column(Text, default="")            # 从谁扩散出来的
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    __table_args__ = (Index("ix_disc_source_time", "source", "created_at"),)


class GraphNode(Base):
    """内置图引擎的节点。props 存原始属性，不裁剪。"""

    __tablename__ = "graph_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(220), unique=True, index=True)   # type:value
    type: Mapped[str] = mapped_column(String(32), index=True)
    label: Mapped[str] = mapped_column(String(300), default="")
    props: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class GraphEdge(Base):
    """内置图引擎的边。同一对节点同一关系只保留一条，权重累加。"""

    __tablename__ = "graph_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src: Mapped[str] = mapped_column(String(220), index=True)
    dst: Mapped[str] = mapped_column(String(220), index=True)
    rel: Mapped[str] = mapped_column(String(48), index=True)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    count: Mapped[int] = mapped_column(Integer, default=1)
    props: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        UniqueConstraint("src", "dst", "rel", name="uq_edge"),
        Index("ix_edge_src_rel", "src", "rel"),
        Index("ix_edge_dst_rel", "dst", "rel"),
    )


class ICPCache(Base):
    """备案查询结果缓存。工信部接口慢且敏感，能缓存就别重复打。"""

    __tablename__ = "icp_cache"

    domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    status: Mapped[str] = mapped_column(String(24), default="unknown")
    license: Mapped[str] = mapped_column(String(80), default="")
    entity: Mapped[str] = mapped_column(String(200), default="")
    nature: Mapped[str] = mapped_column(String(40), default="")
    violation: Mapped[str] = mapped_column(String(16), default="unknown")
    violation_title: Mapped[str] = mapped_column(String(200), default="")
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class TaskRun(Base):
    """长期运行的任务台账。进程重启后据此判断哪些任务烂尾了。"""

    __tablename__ = "task_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)   # discover | enrich | graph | monitor | replica | sandbox
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")


class KeywordHit(Base):
    """词库命中统计。用来发现「哪些词天天误报」「哪些词从没打中过」。"""

    __tablename__ = "keyword_hits"

    term: Mapped[str] = mapped_column(String(120), primary_key=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    confirmed: Mapped[int] = mapped_column(Integer, default=0)
    dismissed: Mapped[int] = mapped_column(Integer, default=0)
    last_hit: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
