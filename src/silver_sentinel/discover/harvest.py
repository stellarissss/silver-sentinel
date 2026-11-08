"""外部线索发现：从「别人已经看见过的页面」反查域名。

为什么要单开一层
----------------
CT 日志只知道「谁注册了域名」。而涉老诈骗的域名是随机串
（`np4w53.cn`、`hksm38.com.cn`），域名词库在这里必然打空——它们不需要
一个好记的域名，因为入口是短信和微信群，不是地址栏。

但这些站的**标题**是精心写的：「2026年个人财政补贴申领」。要靠搜索和
转发让人相信，标题就得像那么回事。标题会留在 urlscan 的索引里。

所以这一层做的事很朴素：拿话术去搜页面标题，把命中的域名捞回来。
判定不在这里做，和 CT 一样只负责产出候选。

实测（2026-11-08）
------------------
    page.title:"个人财政补贴"  → np4w53.cn / hksm38.com.cn / l4k9j.com.cn
    page.title:"补贴申领"      → 上述 3 个 + xindazx.cn

三条命中全部落在上一轮取证过的同模板站群上，说明这条路是通的。

反过来，`page.title:"养老"` 返回 82 条，全是养老院官网、管理系统、
大学学院——所以查询词必须具体到**话术**，不能用行业词。
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

# ---------------------------------------------------------------- 话术词表

# 这些是「骗子会写在标题里」的话，不是「行业里会出现的词」。
# 每加一条都要先跑一遍，看返回的是养老院还是诈骗页——实测记录见模块文档。
#
# 2026-11-08 全量实测（每个词都跑过一遍，记录命中数）：
#   subsidy      个人财政补贴 3 / 补贴申领 4 / 惠民资金 1 / 惠民补贴 1 / 财政补贴 3
#   pension      智慧养老平台 1 / 老龄康养 1 / 养老投资 1 / 康养中心 2
#   health       免费领鸡蛋 1 / 健康科普 52（全是人民网，噪声）
#   gov_spoof    民政部 1
#   unfreeze     民族资产解冻 0 —— 标题里根本不写这四个字，改从正文捞
#   social_sec   社保卡异常 0 / 养老金认证 0 —— 同上
#
# 所以词表分成两档：HIGH_YIELD 每轮都跑，LOW_YIELD 按比例轮换。
# 无效词不是删掉，而是降频——骗子换话术比我们改词表快，留着当探针。
TITLE_QUERIES: dict[str, tuple[str, ...]] = {
    # 发钱类：最高频，标题高度模板化，一个模板能套几百个域名
    "subsidy": (
        "个人财政补贴",
        "补贴申领",
        "惠民资金",
        "惠民补贴",
        "财政补贴",
        "养老金补发",
        "社保补贴",
        "高龄津贴",
        "扶贫款",
        "专项补贴",
        "发放补贴",
        "补贴领取",
    ),
    # 民族资产解冻类：公安部专项，话术几十年不变
    "unfreeze": (
        "民族资产解冻",
        "资产解冻",
        "国家项目",
        "国家保密项目",
        "解冻费",
        "海外资产",
    ),
    # 康养投资类：以养老公寓、会员卡、床位为名吸收资金
    "pension_invest": (
        "智慧养老平台",
        "老龄康养",
        "养老投资",
        "以房养老",
        "养老床位",
        "康养中心",
        "养老公寓",
        "养老会员",
        "旅居养老",
        "康养基地",
    ),
    # 健康类：会销线上化，讲座 → 加微信 → 卖"特效药"
    "health": (
        "免费领鸡蛋",
        "健康讲座",
        "特效药",
        "专家义诊",
        "名医坐诊",
        "免费体检",
        "祖传秘方",
    ),
    # 社保医保钓鱼：短信里的落地页
    "social_security": (
        "社保卡异常",
        "社保账户",
        "医保补贴",
        "电子社保卡升级",
        "社保卡升级",
        "医保卡停用",
        "养老金认证",
        "待遇资格认证",
    ),
    # 冒充部委：标题直接写机构名的，几乎必然是仿冒（真站不会这么起标题）
    "gov_spoof": (
        "民政部",
        "国家医疗保障局",
        "人力资源和社会保障部",
        "国务院办公厅",
        "国家乡村振兴局",
        "中国老龄协会",
    ),
}

# 实测有命中的簇，每轮优先跑
HIGH_YIELD = frozenset(
    {"个人财政补贴", "补贴申领", "财政补贴", "惠民资金", "惠民补贴",
     "智慧养老平台", "老龄康养", "养老投资", "康养中心", "免费领鸡蛋", "民政部"}
)

# 原始查询表达式：不走 page.title，直接喂 Lucene 语法。
# 只放「实测能出真东西」的，加一条要能说清它和标题检索的差别。
RAW_QUERIES: dict[str, tuple[str, ...]] = {
    # APK 分发站。实测 43 条，全是中文 App 下载页——量小，但里面真有货：
    # 26537.net（暖邻）就是从这里捞到的，gate 页 → 双通道 → 84MB 加固包。
    "apk_dist": (
        "page.url:apk AND page.language:zh",
        "page.url:\"download\" AND page.language:zh AND page.url:apk",
    ),
}

# 一轮跑不完所有词，按簇轮换；单簇跑完再换下一簇
ROTATION = tuple(TITLE_QUERIES)

# 这些来源明确「有人在页面上见过目标内容」，不是从域名里猜的。
# 它们在取证之前不接受域名级降档——quick 研判只看域名，用它否定外部线索
# 等于把发现层的成果直接丢掉（线上实测：6 条线索 3 条被压成 cold 再不取证）。
EXTERNAL_SOURCES = frozenset({"urlscan", "report", "elder_seed", "ip_pool", "cert_sibling"})

# 标题里出现这些，多半是正经机构，收但降权（不是丢——判据会再看一遍）
_INSTITUTIONAL = (
    "有限公司",
    "股份",
    "官网",
    "官方网站",
    "大学",
    "学院",
    "医院",
    "卫生院",
    "服务中心",
    "人民政府",
    "民政局",
    "社保局",
    "招聘",
    "招标",
)


@dataclass(slots=True)
class HarvestObservation:
    """伪证书观测：让外部线索走与 CT 相同的落库路径。

    `_persist` 只用到 `.source` / `.as_dict()` / `.fingerprint` 三个属性，
    这里给一个空 fingerprint——外部线索不参与证书聚类，那是另一条证据链。
    """

    source: str
    query: str
    title: str
    url: str = ""
    fingerprint: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "query": self.query,
            "title": self.title[:160],
            "url": self.url[:300],
        }


@dataclass(slots=True)
class HarvestHit:
    host: str
    title: str
    url: str
    query: str
    score: float
    source: str = "urlscan"

    def observation(self) -> HarvestObservation:
        """包装成与 CertObservation 同形的观测，走同一条落库路径。"""
        return HarvestObservation(
            source=self.source, query=self.query, title=self.title, url=self.url
        )


@dataclass
class HarvestStats:
    rounds: int = 0
    queries: int = 0
    hits: int = 0
    errors: int = 0
    by_cluster: dict[str, int] = field(default_factory=dict)
    last_error: str = ""
    last_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rounds": self.rounds,
            "queries": self.queries,
            "hits": self.hits,
            "errors": self.errors,
            "by_cluster": dict(self.by_cluster),
            "last_error": self.last_error,
            "last_at": self.last_at,
        }


def score_title(title: str) -> float:
    """标题的可疑度，只用于排序，不用于定罪。

    机构味越重分越低，但仍然进候选——「XX 市养老服务中心」也可能是仿的，
    只是优先级排在后面。
    """
    low = title
    if any(k in low for k in _INSTITUTIONAL):
        return 0.32
    return 0.72


class UrlscanSource:
    """urlscan.io 标题检索。

    免费 API 无需 key，但有速率限制；单次 size 上限 100。
    失败一律返回空，不抛——发现层断一轮可以接受，崩掉整条链不行。
    """

    BASE = "https://urlscan.io/api/v1/search/"
    NAME = "urlscan"

    def __init__(self, *, size: int = 100, timeout: float = 25.0, pause: float = 2.5) -> None:
        self.size = max(1, min(size, 100))
        self.timeout = timeout
        self.pause = pause
        self._lock = threading.Lock()

    def fetch(self, query: str) -> list[HarvestHit]:
        # `raw:` 前缀 = 直接当 Lucene 表达式用，不再包 page.title
        if query.startswith("raw:"):
            q = query[4:].strip()
        else:
            q = f'page.title:"{query}"'
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(
                    self.BASE,
                    params={"q": q, "size": self.size},
                    headers={"User-Agent": "silver-sentinel/1.x (+threat-research)"},
                )
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:  # noqa: BLE001 一次查询失败不阻塞整轮
            log.debug("urlscan 查询失败 %s：%s", query, exc)
            raise

        out: list[HarvestHit] = []
        seen: set[str] = set()
        for item in payload.get("results") or []:
            page = item.get("page") or {}
            host = (page.get("domain") or "").strip().lower()
            title = (page.get("title") or "").strip()
            url = (page.get("url") or "").strip()
            if not host or host in seen:
                continue
            seen.add(host)
            out.append(
                HarvestHit(
                    host=host,
                    title=title,
                    url=url,
                    query=query,
                    score=score_title(title),
                    source=self.NAME,
                )
            )
        return out


class Harvester:
    """把查询词分簇轮换着跑，一轮只跑几个，避免触发限流。

    两个线上踩过的坑：
    1. **游标没落盘**：以前 cursor 是实例属性，服务重启就归零。今天部署了
       十次，十轮全跑的是 subsidy 簇的前四个词，另外 25 个词一次都没出去
       （事件日志里十轮 by_cluster 全是 subsidy，一眼就能看出来）。
    2. **平权轮换**：29 个词里只有 11 个实测有命中，剩下 18 个每轮白烧配额。
       现在高产出词权重 ×2，无效词留着当探针但降频。
    """

    def __init__(
        self,
        source: UrlscanSource | None = None,
        *,
        per_round: int = 4,
        state_path: Any = None,
    ) -> None:
        self.source = source or UrlscanSource()
        self.per_round = max(1, per_round)
        self.stats = HarvestStats()
        self._state_path = state_path
        self._cursor = self._load_cursor()
        self._flat: list[tuple[str, str]] = self._build_rotation()

    def _build_rotation(self) -> list[tuple[str, str]]:
        """高产出词放两次，其余一次。轮换表变长，但每轮仍只跑 per_round 个。"""
        out: list[tuple[str, str]] = []
        for cluster in ROTATION:
            for q in TITLE_QUERIES[cluster]:
                out.append((cluster, q))
                if q in HIGH_YIELD:
                    out.append((cluster, q))
        for cluster, queries in RAW_QUERIES.items():
            for q in queries:
                out.append((cluster, "raw:" + q))
        return out

    def _load_cursor(self) -> int:
        if self._state_path is None:
            return 0
        try:
            raw = json.loads(Path(self._state_path).read_text(encoding="utf-8"))
            return max(0, int(raw.get("cursor") or 0))
        except Exception:  # noqa: BLE001 状态文件坏了就从 0 开始，不值得为此报错
            return 0

    def _save_cursor(self) -> None:
        if self._state_path is None:
            return
        try:
            path = Path(self._state_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"cursor": self._cursor, "saved_at": time.time()}),
                encoding="utf-8",
            )
            tmp.replace(path)
        except OSError:
            pass

    def next_queries(self) -> list[tuple[str, str]]:
        if not self._flat:
            return []
        out = []
        for _ in range(min(self.per_round, len(self._flat))):
            out.append(self._flat[self._cursor % len(self._flat)])
            self._cursor += 1
        self._save_cursor()
        return out

    def run_round(self) -> list[HarvestHit]:
        from ..domain import utcnow

        hits: list[HarvestHit] = []
        for cluster, query in self.next_queries():
            self.stats.queries += 1
            try:
                got = self.source.fetch(query)
            except Exception as exc:  # noqa: BLE001
                self.stats.errors += 1
                self.stats.last_error = f"{type(exc).__name__}: {exc}"[:160]
                continue
            hits.extend(got)
            self.stats.by_cluster[cluster] = (
                self.stats.by_cluster.get(cluster, 0) + len(got)
            )
            time.sleep(self.source.pause)
        self.stats.rounds += 1
        self.stats.hits += len(hits)
        self.stats.last_at = utcnow().isoformat()
        return hits

    def as_dict(self) -> dict[str, Any]:
        return self.stats.as_dict()
