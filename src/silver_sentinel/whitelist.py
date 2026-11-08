"""白名单：政府网站与新闻媒体。

定位（重要）
------------
**这不是过滤器，是验证器。**

第一版设计里最容易犯的错，是把白名单当成「不在名单里就排除」——那样会把
53kf（客服 SaaS）、易歌科技（建站公司）、39 健康（健康门户）全部判成诈骗，
因为它们一个都不在政府/媒体名单里。全中文互联网 2000 万个 `.cn` 域名，
白名单只有 2.2 万个，覆盖率 0.1%。

白名单只回答一个问题：**「它说它是财政部，那它到底是不是？」**

三种用法：

1. `is_government(host)` —— 域名本身是不是政府站（`.gov.cn` 后缀 + 权威库）；
2. `agency_domains(name)` —— 某个机构名对应的官方域名，用来核对「自称」；
3. `is_media(host)` —— 是不是正规新闻媒体（稿源名单）。

数据来源
--------
- `data/gov_sites.csv.gz`：全国政府网站基本信息数据库（13,333 条），
  经 Vincent Brussee 的 Zenodo 数据集获得（境外直连 zfwzzc.www.gov.cn 会被
  reverse GFW 拦）。字段：host / name / level。
- `data/media_sites.txt`：《互联网新闻信息稿源单位名单》（2025-06，1,451 家）
  中能在域名库里匹配到 URL 的 351 个，加 31 家中央新闻网站。

两者都可以用 `tools/build_whitelist.py` 重新生成。文件缺失时降级为
「只认 `.gov.cn` 后缀」，不会让服务起不来。
"""

from __future__ import annotations

import csv
import gzip
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).with_name("data")
GOV_FILE = DATA_DIR / "gov_sites.csv.gz"
MEDIA_FILE = DATA_DIR / "media_sites.txt"

# 政府网站必须使用 gov.cn 域名（国办《政府网站发展指引》）。
# 注意判断的是「后缀」，不是「包含」——`gov.cn.evil.com` 不是政府站。
GOV_SUFFIX = ".gov.cn"

# 机构名的常见前后缀，归一化时去掉，让「财政部」能对上「中华人民共和国财政部」。
_PREFIX = re.compile(r"^(中华人民共和国|中国共产党|中国|国家|全国)")
_SUFFIX = re.compile(r"(政府网站|门户网站|政府门户网站|官方网站|网站|官网|网)$")

# 从文本里抽机构候选：XX部 / XX局 / XX委员会 / XX办公室 / XX中心 …
# 不用「13k 个机构名逐个 in 文本」——那要 300 字 × 13k 次比较，单页 0.2 秒。
# 反向先抽候选，再查索引，通常只有几个候选。
_CANDIDATE = re.compile(
    r"[\u4e00-\u9fff]{2,20}(?:部|局|委员会|办公室|中心|厅|署|总局|管理局|协会|基金会)"
)

# 手工别名：页面上的简称 → 库里的规范名。
# 只补「查不到会漏判」的高频简称，不做全量同义词。
ALIASES = {
    # 政府网站库里"国务院"登记为"中国政府网"（www.gov.cn，国办主办）
    "国务院": "中国政府网",
    "国务院办公厅": "中国政府网",
    "中央人民政府": "中国政府网",
    "国办": "中国政府网",
    "卫健委": "国家卫生健康委员会",
    "卫计委": "国家卫生健康委员会",
    "人社部": "人力资源和社会保障部",
    "人社": "人力资源和社会保障部",
    "财政部": "财政部",
    "税务总局": "国家税务总局",
    "市监总局": "国家市场监督管理总局",
    "市场监管总局": "国家市场监督管理总局",
    "医保局": "国家医疗保障局",
    "退役军人部": "退役军人事务部",
    "发改委": "国家发展和改革委员会",
    "网信办": "国家互联网信息办公室",
    "中央网信办": "国家互联网信息办公室",
    "工信部": "工业和信息化部",
    "公安部": "公安部",
    "民政部": "民政部",
    "农业农村部": "农业农村部",
    "银保监会": "国家金融监督管理总局",
    "金融监管总局": "国家金融监督管理总局",
    "证监会": "中国证券监督管理委员会",
    "老龄办": "全国老龄工作委员会办公室",
    "全国老龄办": "全国老龄工作委员会办公室",
    "中国老龄协会": "中国老龄协会",
}


# 高频被冒用的机构，直接做子串扫描。
# 正则候选（`XX部/XX局` 结尾）在「审核机构 国务院办公厅」这种写法上会切错——
# 会把「审核机构国务院办公厅」整串当成机构名。先用核心表兜住常见情况，
# 再让正则去捞长尾。
CORE_AGENCIES = (
    "国务院办公厅", "国务院", "中央人民政府", "财政部", "国家税务总局", "民政部",
    "人力资源和社会保障部", "人社部", "国家卫生健康委员会", "卫健委",
    "国家市场监督管理总局", "市场监管总局", "公安部", "国家医疗保障局", "医保局",
    "退役军人事务部", "农业农村部", "国家发展和改革委员会", "发改委",
    "国家互联网信息办公室", "网信办", "工业和信息化部", "工信部", "教育部",
    "住房和城乡建设部", "商务部", "文化和旅游部", "应急管理部", "国家统计局",
    "国家信访局", "国家乡村振兴局", "中国老龄协会", "全国老龄工作委员会",
    "国家金融监督管理总局", "银保监会", "中国证券监督管理委员会", "证监会",
    "中国红十字会", "中国科学技术协会", "中国社会福利基金会",
)


def normalize_name(name: str) -> str:
    s = re.sub(r"\s+", "", name or "")
    s = _PREFIX.sub("", s)
    s = _SUFFIX.sub("", s)
    return s


@dataclass(slots=True)
class AgencyHit:
    name: str
    official_domains: list[str] = field(default_factory=list)


class Whitelist:
    def __init__(self) -> None:
        self.gov_hosts: set[str] = set()
        self.gov_names: dict[str, str] = {}          # host -> 单位名
        self.media_hosts: set[str] = set()
        self._agency: dict[str, list[str]] = {}      # 归一化机构名 -> 官方域
        self._agency_display: dict[str, str] = {}
        self.loaded = False
        self.error = ""

    # ------------------------------------------------------------ 加载
    def load(self) -> Whitelist:
        try:
            self._load_gov()
        except FileNotFoundError:
            self.error = f"缺少 {GOV_FILE.name}，政府库降级为 .gov.cn 后缀"
            log.warning("政府网站数据缺失，仅按后缀判定")
        except Exception as exc:  # noqa: BLE001 数据坏了不能拖垮服务
            self.error = f"政府库加载失败：{exc}"
            log.warning("政府库加载失败：%s", exc)
        try:
            self._load_media()
        except FileNotFoundError:
            log.warning("媒体白名单缺失，媒体判定停用")
        except Exception as exc:  # noqa: BLE001
            log.warning("媒体白名单加载失败：%s", exc)
        self.loaded = True
        log.info(
            "白名单就绪：政府 %d 主机 / 媒体 %d 主机 / 机构 %d",
            len(self.gov_hosts), len(self.media_hosts), len(self._agency),
        )
        return self

    def _load_gov(self) -> None:
        with gzip.open(GOV_FILE, "rt", encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                host = (row.get("host") or "").strip().lower()
                name = (row.get("name") or "").strip()
                if not host or "." not in host:
                    continue
                self.gov_hosts.add(host)
                if name:
                    self.gov_names.setdefault(host, name)
                    self._index_agency(name, host)

    def _load_media(self) -> None:
        for line in MEDIA_FILE.read_text(encoding="utf-8").splitlines():
            host = line.strip().lower()
            if host and not host.startswith("#") and "." in host:
                self.media_hosts.add(host)

    def _index_agency(self, name: str, host: str) -> None:
        for key in {normalize_name(name), name}:
            if not key:
                continue
            self._agency.setdefault(key, [])
            if host not in self._agency[key]:
                self._agency[key].append(host)
            self._agency_display.setdefault(key, name)

    # ------------------------------------------------------------ 查询
    @staticmethod
    def _host_matches(host: str, entry: str) -> bool:
        host = (host or "").lower().strip(".")
        return host == entry or host.endswith("." + entry)

    def is_government(self, host: str) -> bool:
        """`.gov.cn` 后缀，或命中权威政府库（含 68 个非 gov.cn 的政府站）。"""
        host = (host or "").lower().strip(".")
        if not host:
            return False
        if host == "gov.cn" or host.endswith(GOV_SUFFIX):
            return True
        # 权威库还收录了 68 个非 gov.cn 的政府站（公共资源交易中心等），
        # 按后缀逐级退着查，避免 13k 次全表扫描。
        return any(c in self.gov_hosts for c in self._gov_candidates(host))

    def _gov_candidates(self, host: str):
        """按后缀逐级退，避免 13k 次全表扫描。"""
        parts = host.split(".")
        out = []
        for i in range(len(parts) - 1):
            out.append(".".join(parts[i:]))
        return out

    def is_media(self, host: str) -> bool:
        host = (host or "").lower().strip(".")
        if not host:
            return False
        for entry in self._media_candidates(host):
            if entry in self.media_hosts:
                return True
        return False

    def _media_candidates(self, host: str):
        parts = host.split(".")
        for i in range(len(parts) - 1):
            yield ".".join(parts[i:])

    def agency_domains(self, name: str) -> list[str]:
        key = normalize_name(name)
        if key in self._agency:
            return list(self._agency[key])
        if name in self._agency:
            return list(self._agency[name])
        alias = ALIASES.get(name) or ALIASES.get(key)
        if alias:
            for k in (normalize_name(alias), alias):
                if k in self._agency:
                    return list(self._agency[k])
        return []

    def match_agencies(self, text: str) -> list[AgencyHit]:
        """从一段「自称」文本里找出它声称的机构，并附上官方域名。

        只对页头/版权行调用，不要喂正文——正文里「据财政部消息」不是自称。
        """
        seen: dict[str, AgencyHit] = {}
        flat = re.sub(r"\s+", "", text or "")
        # 第一层：核心机构表，直接子串命中（长名优先，避免"国务院"抢走"国务院办公厅"）
        for name in sorted(CORE_AGENCIES, key=len, reverse=True):
            if name not in flat:
                continue
            domains = self.agency_domains(name)
            if not domains:
                continue
            key = normalize_name(name) or name
            if key not in seen:
                seen[key] = AgencyHit(name=name, official_domains=domains)
        # 第二层：正则捞长尾（地方局、委员会等）
        for raw in _CANDIDATE.findall(flat):
            for name in (raw, normalize_name(raw)):
                if not name or len(name) < 3:
                    continue
                domains = self.agency_domains(name)
                if not domains:
                    continue
                key = normalize_name(name)
                if key not in seen:
                    seen[key] = AgencyHit(name=name, official_domains=domains)
                break
        return list(seen.values())

    def stats(self) -> dict:
        return {
            "gov_hosts": len(self.gov_hosts),
            "media_hosts": len(self.media_hosts),
            "agencies": len(self._agency),
            "error": self.error,
        }


_whitelist: Whitelist | None = None
_lock = threading.Lock()


def get_whitelist() -> Whitelist:
    global _whitelist
    if _whitelist is None:
        with _lock:
            if _whitelist is None:
                _whitelist = Whitelist().load()
    return _whitelist


def reload_whitelist() -> Whitelist:
    global _whitelist
    with _lock:
        _whitelist = Whitelist().load()
    return _whitelist
