"""词库引擎：把「什么东西值得看一眼」编码成可匹配的知识。

设计要点
--------
1. **词库只维护中文**，拼音变体由 pypinyin 自动派生。骗子注册域名用拼音，
   用中文词表手工维护两遍必然会漏。
2. **按语义簇分组**。同一簇内的多个词命中只算一次加强，避免「养老康养银发」
   三个词把分数堆到天上，掩盖真正有区分度的信号。
3. **宁可错杀**。任何单词命中即进候选池；分数只决定队列顺序，不决定是否收。
4. **白名单保守**。只排除 .gov.cn / .edu.cn 和明确列出的官方域，
   不做「看起来像正规」的猜测——那正是骗子想要的效果。

匹配三种形态：
- 中文：直接子串匹配（域名极少用中文，主要用于标题、页面、话术）
- 拼音：域名 label 去掉连字符/数字后做子串匹配，长词优先
- 缩写：少量高频词的拼音首字母，如 gh(国惠)、mz(民族)——仅当整 label 恰好等于时才算
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from functools import lru_cache

from pypinyin import lazy_pinyin

# ---------------------------------------------------------------- 语义簇

# 权重含义：该词单独出现时，这条线索「值得优先看」的程度（0-1）。
# 不是定罪强度——定罪在 scoring 里做，这里只排序。
CLUSTERS: dict[str, dict] = {
    # 骗局专属：出现即高度可疑，属于公安部专项打击的定性手法
    "scam_signature": {
        "weight": 0.95,
        "terms": [
            "民族资产解冻", "资产解冻", "民族大业", "云数贸", "中国梦平台",
            "1040工程", "阳光工程", "资本运作", "自愿连锁", "互助盘", "拆分盘",
            "资金盘", "杀猪盘", "刷单返利", "解冻费", "报单", "排单", "见点奖",
            "对碰奖", "领导奖", "直推奖", "团队长", "发展下线", "拉人头",
            "原始股", "股权认购", "消费返利", "购物全返", "静态收益", "动态收益",
            "国家保密项目", "保密工程", "内部指标", "特批名额",
            "解冻", "资产恢复", "资产兑现", "认领资产", "云数贸", "五行币",
            "善心汇", "民族大业", "慈善富民", "爱心基金", "养老基金",
            "互助金", "众筹建房", "消费养老", "以房养老", "房养老",
        ],
    },
    # 冒充机构：骗子最爱借的名义
    "authority": {
        "weight": 0.85,
        "terms": [
            "国科", "中科", "中国科学", "社科院", "发改委", "工信部", "民政部",
            "财政部", "人社部", "卫健委", "医保局", "住建部", "农业农村部",
            "民政局", "老龄办", "乡村振兴局", "退役军人事务部", "全国老龄", "老龄委", "老龄协会",
            "中国老龄", "供销总社", "供销社", "全国总工会", "全国妇联", "残联",
            "红十字会", "中华慈善", "中国福利", "国家开发银行", "农业发展银行",
            "社保基金", "全国社保", "公积金", "国家电网", "中储粮", "国铁集团",
            "中国邮政", "广电总局", "市场监管总局", "药监局", "中医药局",
            "国务院", "全国人大", "全国政协", "中央军委", "退役军人",
            "国扶办", "扶贫办", "移民局", "粮食局", "能源局", "林草局",
            "国惠", "国计", "国投", "国储", "国建", "国创", "国康", "国养",
            "惠民工程", "惠民补贴", "富民", "安民", "利民", "为民",
        ],
    },
    # 被冒用的商业品牌。骗子做「快手银发」「抖音养老」这类，品牌词必须参与匹配。
    "brand": {
        "weight": 0.80,
        "terms": [
            "kuaishou", "douyin", "weixin", "wechat", "alipay", "taobao",
            "tmall", "pinduoduo", "jingdong", "unionpay", "icbc", "ccb",
            "abchina", "boc", "psbc", "cmb", "chinaunicom", "chinamobile",
            "chinatelecom", "sinopec", "cnpc", "stategrid", "chinapost",
            # "people" 是英文常用名词，oceanpeople / purepeople / valuablepeople
            # 这类正经站会被整批误判成「冒充人民日报」，实测一天 736 次。
            "chinalife", "cctv", "xinhua", "toutiao", "meituan",
            "didi", "xiaomi", "huawei", "tencent", "alibaba", "baidu",
        ],
    },
    # 政策主题：涉老、涉农、涉补贴。单独不足以定性，但决定监控方向
    "policy_theme": {
        "weight": 0.55,
        "terms": [
            "养老", "康养", "医养", "银发", "老年", "退休", "离休", "社保",
            "医保", "新农合", "农保", "低保", "五保", "特困", "救助", "抚恤",
            "优抚", "助残", "扶贫", "脱贫", "乡村振兴", "共同富裕", "惠农",
            "助农", "三农", "合作社", "集体经济", "数字货币", "数字人民币",
            "碳中和", "碳达峰", "东数西算", "西部大开发", "一带一路", "自贸区",
            "雄安", "光伏", "新能源", "储能", "芯片", "半导体", "专精特新",
            "小巨人", "高新技术", "科技补贴", "创新基金", "专项资金",
            "扶持资金", "稳岗补贴", "就业补贴", "创业补贴", "生育补贴",
            "育儿补贴", "教育补贴", "助学", "奖学金", "危房改造", "拆迁",
            "棚改", "旧改", "安置房", "保障房", "廉租房", "土地流转",
            "宅基地", "退耕还林", "粮食补贴", "农机补贴", "种子补贴",
            "养殖补贴", "以工代赈", "公益岗", "灵活就业", "军属", "烈属",
            "知青", "下乡", "支边", "五七工", "家属工", "民办教师",
            "乡村医生", "代课教师", "养老金", "退休金", "高龄补贴", "护理补贴",
            "医疗保险", "参保", "缴费", "社保卡", "医保卡", "退休人员",
            "老年大学", "日间照料", "居家养老", "社区养老", "机构养老",
            "老龄", "乐龄", "夕阳红", "安养", "颐养", "康养中心", "养老社区",
            "长寿", "百岁", "养生馆", "健康管理", "慢病", "三高", "糖尿病",
            "心脑血管", "肿瘤", "抗癌", "免疫", "营养素", "保健品", "理疗仪",
        ],
    },
    # 免费诱导：领鸡蛋骗局的入口特征
    "inducement": {
        "weight": 0.72,
        "terms": [
            "免费领", "免费送", "免费拿", "免费测", "免费体验", "免费体检",
            "领鸡蛋", "送鸡蛋", "鸡蛋", "米面油", "粮油", "礼品", "赠品",
            "到场即送", "签到领", "每日签到", "红包", "现金红包", "福利",
            "健康讲座", "专家义诊", "义诊", "免费旅游", "康养旅游", "旅居",
            "养生", "保健", "特效药", "神药", "根治", "祖传", "秘方",
            "包治百病", "细胞修复", "干细胞", "量子", "磁疗", "理疗",
        ],
    },
    # 载体：说明这是一个「平台」，需要配合上面任一类才有意义
    "carrier": {
        "weight": 0.32,
        "terms": [
            "APP", "应用", "平台", "系统", "中心", "网站", "官网", "公众号",
            "小程序", "客服", "专员", "主任", "处长", "局长", "部长",
            "理事长", "秘书长", "工作站", "办事处", "服务中心", "申报",
            "申领", "领取", "发放", "登记", "注册", "认证", "实名", "激活",
            "审核", "名额", "指标", "额度", "绿色通道", "专项通道",
            "内部通道", "特批", "试点", "惠民", "国补", "国家补贴",
            "财政补贴", "福利", "分红", "股权", "上市", "众筹", "互助",
            "基金", "基金", "入股", "认购", "份额", "配额", "工单", "专员对接",
        ],
    },

    # ---------------------------------------------------------------- v1.5 扩展
    # 下面这些簇不是从新闻标题里抄的，而是按「团伙怎么造词」推出来的：
    # 曝光词会被规避，但「养老服务 + 补贴 + 领取」这个语义结构不会变。
    # 所以宁可收宽一点，靠 WEAK_ONLY 降权、靠取证与内容规则收敛。

    # 养老服务：正规业态与骗局共用同一批词，单独出现绝不能定性
    "elder_care": {
        "weight": 0.45,
        "terms": [
            "养老院", "敬老院", "福利院", "托老所", "日间照料", "老年食堂",
            "助餐点", "助浴", "适老化改造", "老年大学", "银发经济", "康养中心",
            "康养基地", "养生基地", "温泉疗养", "旅居养老", "候鸟养老", "互助养老",
            "时间银行", "抱团养老", "以房养老", "房养老", "床位预订", "会员卡",
            "预付费", "护理院", "康复中心", "中医馆", "国医馆", "理疗馆",
            "艾灸馆", "体验店", "会销", "会议营销", "健康讲座", "专家讲座",
            "免费体检", "慢病管理", "健康管理", "养老公寓", "养老社区", "会员制养老",
            "颐养", "安养", "乐龄", "夕阳红", "长寿村", "生态养老",
        ],
    },
    # 保健品会销：词很具体，命中即说明页面在卖「疗效」
    "health_product": {
        "weight": 0.6,
        "terms": [
            "保健食品", "膳食补充剂", "营养素", "蛋白粉", "羊奶粉", "驼奶粉",
            "蜂胶", "蜂王浆", "灵芝孢子粉", "纳豆", "辅酶", "氨糖",
            "软骨素", "胶原蛋白", "酵素", "益生菌", "小分子肽", "免疫细胞",
            "白藜芦醇", "虾青素", "叶黄素", "鱼油", "卵磷脂", "三七",
            "天麻", "藏药", "蒙药", "苗药", "偏方", "秘方",
            "药到病除", "细胞修复", "排毒", "酸碱体质", "微循环", "疏通经络",
            "理疗床", "按摩椅", "足疗仪", "氢气机", "富氢水", "能量石",
            "生物电", "远红外", "负离子", "富硒", "小分子水", "弱碱性水",
            "磁化水", "频谱仪", "太赫兹", "心脑血管", "防癌", "抗癌",
            "抗衰", "逆龄", "长寿",
        ],
    },
    # 投资理财：资金盘的外壳换了一茬又一茬，结构词不变
    "investment": {
        "weight": 0.7,
        "terms": [
            "原始股", "股权认购", "期权", "外汇", "期货", "现货",
            "数字货币", "虚拟货币", "挖矿", "矿机", "元宇宙", "数字藏品",
            "碳积分", "碳交易", "光伏电站", "充电桩", "民宿托管", "商铺返租",
            "车位返租", "产权酒店", "养老地产", "康养地产", "文旅地产", "共享经济",
            "消费商", "分享经济", "直销", "传销", "微商", "招商加盟",
            "众筹", "互助盘", "拆分盘", "资金盘", "杀猪盘", "刷单",
            "消费全返", "购物全返", "积分返现", "签到赚钱", "看广告赚钱", "走路赚钱",
            "睡觉赚钱", "挂机赚钱", "游戏搬砖", "代理分红", "团队计酬", "多层分销",
        ],
    },
    # 国家项目：这一簇是「政策伪装」的核心，权重接近骗局专属词
    "project_scam": {
        "weight": 0.88,
        "terms": [
            "国家项目", "国家工程", "秘密工程", "保密项目", "军民融合", "北斗",
            "东数西算", "西气东输", "南水北调", "西电东送", "雄安新区", "自贸区",
            "共同富裕", "第三次分配", "全民持股", "全民分红", "国家红利", "改革红利",
            "政策红利", "扶贫款", "扶贫资金", "专项扶贫", "以工代赈", "退耕还林",
            "粮食补贴", "农机补贴", "种子补贴", "养殖补贴", "危房改造", "棚户区改造",
            "旧城改造", "拆迁补偿", "征地补偿", "安置房", "保障房", "廉租房",
            "公租房", "土地流转", "宅基地", "确权", "补贴申领", "惠民工程",
            "专项资金", "扶持资金", "稳岗补贴", "就业补贴", "创业补贴", "生育补贴",
            "育儿补贴", "教育补贴", "奖学金", "高龄补贴", "护理补贴", "养老服务补贴",
        ],
    },
    # 特定人群称谓：精准筛选「有历史遗留诉求」的老人
    "honorific": {
        "weight": 0.5,
        "terms": [
            "老同志", "老战友", "老干部", "老教师", "老工人", "老知青",
            "军属", "烈属", "伤残军人", "复员军人", "退伍军人", "退役军人",
            "五七工", "家属工", "民办教师", "代课教师", "赤脚医生", "乡村医生",
            "三线建设", "支边", "返乡", "侨眷", "台属", "归侨",
            "退休职工", "离休干部", "内退", "病退", "特殊工种", "工龄买断",
            "买断工龄", "社保补缴", "一次性补缴", "视同缴费",
        ],
    },
    # 私域渠道：把人从可审计的平台拉走，是几乎所有涉老骗局的固定一步
    "channel": {
        "weight": 0.4,
        "terms": [
            "微信群", "企业微信", "视频号", "快手群", "抖音群", "钉钉群",
            "腾讯会议", "瞩目", "小鹅通", "有播", "微赞", "看点直播",
            "直播带货", "私域", "社群", "团长", "社区团购", "拼团",
            "接龙", "群接龙", "服务号", "订阅号", "快手小店", "抖音小店",
            "淘宝客", "淘客", "二级分销", "三级分销", "拉群", "建群",
            "进群", "群公告", "群主",
        ],
    },
    # 资金通道：出现在页面上就是「钱往哪走」的直接线索
    "payment": {
        "weight": 0.55,
        "terms": [
            "收款码", "收款账户", "对公账户", "私人账户", "银行卡号", "支付宝转账",
            "微信转账", "扫码支付", "POS机", "套现", "代还", "养卡",
            "跑分", "洗钱", "水房", "四件套", "银行卡四件套", "流量卡",
            "USDT", "泰达币", "冷钱包", "热钱包", "充值", "提现",
            "保证金", "认购款", "报名费", "材料费", "工本费", "解冻费",
            "公证费", "税费",
        ],
    },
    # 新技术噱头：骗子最爱把「看不懂的词」包装成疗效或收益
    "ai_hype": {
        "weight": 0.5,
        "terms": [
            "AI体检", "AI中医", "AI算命", "AI看相", "AI养老", "智能养老",
            "智慧养老", "基因检测", "干细胞治疗", "免疫治疗", "生物科技", "脑机接口",
            "量子科技", "量子纠缠", "量子鞋垫", "量子床垫",
        ],
    },
    # 收藏品：高价回购话术的载体
    "collectible": {
        "weight": 0.5,
        "terms": [
            "纪念币", "纪念钞", "连体钞", "错版币", "字画", "瓷器",
            "玉器", "玉石", "陨石", "红木", "老酒", "藏品",
            "拍卖", "鉴定", "评估", "回购", "升值", "传世",
            "国宝", "文物", "古董",
        ],
    },
    # 旅游养老：低价团 + 康养基地，落地后转推销
    "travel_elder": {
        "weight": 0.45,
        "terms": [
            "低价游", "免费游", "康养游", "旅居", "巴马", "度假村",
            "疗养院", "疗养基地", "农家乐", "温泉",
        ],
    },
    # 运营黑话：正规营销/代运营/投票 SaaS 页面每天都在写。
    # 权重压到最低，且刻意不算「强簇」——它只提供场景上下文，不能单独定性。
    "sales_jargon": {
        "weight": 0.3,
        "terms": [],
    },
    # 谐音与错别字：团伙为了绕开平台关键词审查，会主动写错
    "variant": {
        "weight": 0.6,
        "terms": [
            "果补", "惠珉", "惠敏", "汇民", "解栋", "解东",
            "乡付", "乡助", "共富", "数币", "养佬", "氧老",
            "补帖", "扶平", "股全", "分宏", "反利", "投姿",
            "里财", "银航", "保显", "基今",
        ],
    },
}

# 词库扩展包：按簇追加，集中在一处，便于按命中率整批回滚。
# 来源不是新闻标题，而是「这类骗局需要哪些词才能把老人筛出来」的推理：
# 人群、场景、政策、渠道、资金，每一层都有固定词汇。
_EXTENSIONS: dict[str, list[str]] = {
    # 老年人日常生活与健康场景：单独毫无意义，但与「补贴/领取/专家」同现时指向性很强
    "policy_theme": [
        "个人养老金", "税收优惠", "专项附加扣除", "灵活就业社保", "城乡居民养老",
        "城乡居民医保", "大病保险", "医疗救助", "临时救助", "特困供养",
        "残疾人补贴", "两项补贴", "高龄津贴", "敬老月", "老年节",
        "重阳节", "银龄行动", "智慧助老", "家庭养老床位", "社区嵌入式养老",
        "老年助餐", "互助幸福院", "农村幸福院", "日间照料中心", "居家养老服务",
        "政府购买服务", "失能补贴", "评估等级", "长期护理险", "惠民保",
        "异地就医", "门诊统筹", "医保报销", "公积金提取", "企业年金",
        "职业年金", "养老保险", "遗嘱", "遗产", "信托",
    ],
    "inducement": [
        "免费鸡蛋", "鸡蛋券", "领挂面", "领大米", "领食用油", "领抽纸",
        "领洗衣液", "免费理疗", "免费测血糖", "免费测血压", "免费听讲座",
        "专家面对面", "名医坐诊", "义诊活动", "健康筛查", "癌症筛查",
        "基因筛查", "免费住院", "免费吃药", "试吃",
        "体验装", "赠品券", "代金券", "抵用券", "消费券",
        "积分兑换", "会员日", "生日礼", "老带新", "介绍有礼",
    ],
    # 真正的黑话：团伙内部用语，正规营销不会写。
    # 「引流 / 转化 / 复购 / 讲师 / 区域经理」这些曾被放在这里，实测把
    # 微信投票 SaaS（weixin100.com.cn，页面写「高效引流方案」）直接推成 51 分
    # 进自动盯防——它们只是运营通用词，已移到 sales_jargon 用低权重计。
    "scam_signature": [
        "话术本", "剧本", "洗脑", "盯人", "报单中心", "团队计酬",
        "拉新奖励", "首单奖励", "复投", "锁仓", "养号",
    ],
    # 运营黑话：销售/代运营/私域 SaaS 页面天天出现，单独出现毫无定性价值。
    # 存在的意义只是「会销、拉群、逼单」这类场景的弱上下文，
    # 权重压到 0.30，且不属于强簇，不参与 KW-001 的强主题词判定。
    "sales_jargon": [
        "引流", "转化", "复购", "裂变", "地推", "跟单", "关单",
        "逼单", "气氛组", "讲师", "督导", "区域经理", "大区", "话术",
    ],
    "authority": [
        "中国老龄事业发展基金会", "中国老年大学协会", "中国老年保健协会",
        "中国保健协会", "中国中医药协会", "中华医学会", "中国营养学会",
        "全国老龄办", "国家老龄办", "离退休干部局", "老干部局", "干休所",
        "军休所", "优抚医院", "荣军医院", "社会福利中心", "救助管理站",
        "关心下一代工作委员会", "老区建设促进会", "老龄产业协会",
    ],
    # 数字生活场景：冒充客服/退费类必然出现
    "channel": [
        "电子社保卡", "掌上12333", "国家医保服务平台", "个人所得税",
        "健康码", "行程卡", "电子身份证", "人脸认证", "短信验证码",
        "屏幕共享", "远程控制", "投屏", "手机管家", "广告弹窗",
        "中奖", "快递", "退货", "退款", "400电话", "95开头", "境外来电",
    ],
    "health_product": [
        "血压", "血糖", "血脂", "心电", "睡眠", "失眠",
        "便秘", "骨质疏松", "白内障", "老花眼", "助听器", "轮椅",
        "拐杖", "护理床", "纸尿裤", "钙片", "维生素", "鱼肝油",
        "阿胶", "人参", "鹿茸", "冬虫夏草", "燕窝", "石斛",
        "黄芪", "枸杞", "艾草", "拔罐", "刮痧", "推拿",
        "针灸", "理疗", "体检报告", "化验单", "专家号", "陪诊",
        "护工", "保姆", "家政", "临终关怀", "墓地", "寿衣",
    ],
}

for _cluster, _extra in _EXTENSIONS.items():
    if _cluster in CLUSTERS:
        CLUSTERS[_cluster]["terms"].extend(_extra)

# 地区词只用于「组合生成」，不参与域名匹配：
# hebei / shanxi 这种拼音出现在大量正常域名里，直接匹配必然误报。
REGIONS: list[str] = [
    "北京", "上海", "天津", "重庆", "河北", "河南", "山东", "山西", "陕西",
    "辽宁", "吉林", "黑龙江", "江苏", "浙江", "安徽", "福建", "江西", "湖北",
    "湖南", "广东", "广西", "海南", "四川", "贵州", "云南", "西藏", "甘肃",
    "青海", "宁夏", "新疆", "内蒙古", "石家庄", "唐山", "保定", "邯郸",
    "郑州", "洛阳", "南阳", "济南", "青岛", "烟台", "临沂", "太原", "西安",
    "沈阳", "大连", "长春", "哈尔滨", "南京", "苏州", "无锡", "徐州", "杭州",
    "宁波", "温州", "合肥", "福州", "厦门", "南昌", "武汉", "长沙", "广州",
    "深圳", "佛山", "东莞", "南宁", "海口", "成都", "绵阳", "贵阳", "昆明",
    "兰州", "银川", "乌鲁木齐", "呼和浩特",
]

# 组合词的另一半：团伙命名时高频使用，但单独作为域名没有信息量
COMBINE_SUFFIXES: list[str] = [
    "惠民", "民生", "富民", "利民", "安民", "为国", "中科", "国科",
    "康养", "颐养", "养老", "银发", "乐龄", "夕阳", "长寿", "健康",
    "补贴", "补助", "福利", "公益", "慈善", "助老", "敬老", "爱老",
    "乡村", "振兴", "共富", "数字", "科技", "工程", "项目", "中心",
]

# 极高的误报源：这些词只有在和「机构词」或「骗局词」同时出现时才计分。
# 例如「鸡蛋」本身是正常商品，「体检」是正常服务。
WEAK_ONLY = {
    "鸡蛋", "米面油", "粮油", "礼品", "赠品", "红包", "福利", "养生", "保健",
    "体检", "义诊", "旅游", "积分", "签到", "客服", "中心", "平台", "系统",
    "应用", "官网", "网站", "登记", "注册", "认证", "实名", "审核", "名额",
    "指标", "额度", "上市", "股权", "分红", "互助", "老年", "退休",
    "免费测", "服务中心", "血压", "测量", "讲座", "量血压", "测血糖",
    "医疗保险", "参保", "缴费", "社保卡", "医保卡", "退休人员",
    "老年大学", "日间照料", "居家养老", "社区养老", "机构养老",
    "基金", "入股", "份额", "配额", "工单", "专员对接", "试点",
    # ---- v1.5 扩展：这些词单独出现完全正常，靠组合与取证收敛
    "养老院", "敬老院", "福利院", "托老所", "老年食堂", "助餐点", "助浴",
    "适老化改造", "银发经济", "康养中心", "康养基地", "养生基地", "温泉疗养",
    "旅居养老", "候鸟养老", "互助养老", "时间银行", "抱团养老", "以房养老",
    "床位预订", "会员卡", "预付费", "护理院", "康复中心", "中医馆", "国医馆",
    "理疗馆", "艾灸馆", "体验店", "会销", "会议营销", "健康讲座", "专家讲座",
    "免费体检", "慢病管理", "健康管理", "养老公寓", "养老社区", "会员制养老",
    "颐养", "安养", "乐龄", "夕阳红", "长寿村", "生态养老",
    "保健食品", "膳食补充剂", "营养素", "蛋白粉", "羊奶粉", "驼奶粉", "蜂胶",
    "蜂王浆", "灵芝孢子粉", "纳豆", "辅酶", "氨糖", "软骨素", "胶原蛋白",
    "酵素", "益生菌", "鱼油", "卵磷脂", "三七", "天麻", "藏药", "蒙药",
    "苗药", "偏方", "秘方", "理疗床", "按摩椅", "足疗仪", "心脑血管", "三高",
    "糖尿病", "肿瘤", "抗衰", "长寿",
    "原始股", "股权认购", "期权", "外汇", "期货", "现货", "数字货币",
    "虚拟货币", "挖矿", "矿机", "元宇宙", "数字藏品", "碳积分", "碳交易",
    "光伏电站", "充电桩", "民宿托管", "商铺返租", "车位返租", "产权酒店",
    "养老地产", "康养地产", "文旅地产", "共享经济", "消费商", "分享经济",
    "直销", "微商", "招商加盟", "众筹", "刷单", "返利",
    "国家项目", "国家工程", "秘密工程", "军民融合", "北斗", "自贸区",
    "雄安新区", "共同富裕", "扶贫款", "扶贫资金", "粮食补贴", "农机补贴",
    "种子补贴", "养殖补贴", "危房改造", "棚户区改造", "旧城改造", "拆迁补偿",
    "征地补偿", "安置房", "保障房", "廉租房", "公租房", "土地流转", "宅基地",
    "确权", "专项资金", "扶持资金", "奖学金",
    "老同志", "老战友", "老干部", "老教师", "老工人", "老知青", "军属",
    "烈属", "复员军人", "退伍军人", "退役军人", "民办教师", "代课教师",
    "乡村医生", "支边", "返乡", "侨眷", "台属", "归侨", "退休职工",
    "离休干部", "内退", "病退", "特殊工种", "工龄买断", "买断工龄",
    "社保补缴", "一次性补缴", "视同缴费",
    "微信群", "企业微信", "视频号", "钉钉群", "腾讯会议", "瞩目", "小鹅通",
    "有播", "微赞", "直播带货", "私域", "社群", "团长", "社区团购", "拼团",
    "接龙", "群接龙", "服务号", "订阅号", "淘宝客", "淘客", "二级分销",
    "三级分销", "拉群", "建群", "进群", "群公告", "群主",
    "收款码", "收款账户", "对公账户", "私人账户", "银行卡号", "支付宝转账",
    "微信转账", "扫码支付", "POS机", "套现", "代还", "养卡", "跑分", "洗钱",
    "水房", "四件套", "流量卡", "冷钱包", "热钱包", "充值", "提现",
    "保证金", "认购款", "报名费", "材料费", "工本费", "公证费", "税费",
    "AI体检", "AI中医", "AI算命", "AI看相", "AI养老", "智能养老", "智慧养老",
    "基因检测", "干细胞治疗", "免疫治疗", "生物科技", "脑机接口", "量子科技",
    "量子纠缠", "纪念币", "纪念钞", "连体钞", "错版币", "字画", "瓷器",
    "玉器", "玉石", "陨石", "红木", "老酒", "藏品", "拍卖", "鉴定", "评估",
    "回购", "升值", "传世", "国宝", "文物", "古董", "低价游", "免费游",
    "康养游", "旅居", "巴马", "度假村", "疗养院", "疗养基地", "农家乐", "温泉",
}

# 明确白名单：政府与教育机构域名，以及少数已知官方主域。
# 保持极窄——骗子也会注册 xxx-gov.cn 这样的域名，绝不能按「包含 gov」放行。
WHITELIST_SUFFIXES = (".gov.cn", ".edu.cn", ".mil.cn", ".ac.cn")
WHITELIST_DOMAINS = {
    "gov.cn", "12377.cn", "12321.cn", "12315.cn", "mps.gov.cn", "miit.gov.cn",
    "nhc.gov.cn", "mca.gov.cn", "mof.gov.cn", "mohrss.gov.cn", "npc.gov.cn",
    "court.gov.cn", "spp.gov.cn", "chinacourt.org", "people.com.cn", "xinhuanet.com",
    "cctv.com", "chinadaily.com.cn", "gov.hk", "gov.mo",
    # 真实平台官方域，避免把自家域名当仿冒
    "kuaishou.com", "douyin.com", "weixin.qq.com", "qq.com", "alipay.com",
    "taobao.com", "tmall.com", "jd.com", "pinduoduo.com", "weibo.com",
    "baidu.com", "tencent.com", "alibaba.com", "bilibili.com",
}

# 高频拼音缩写：只在整段 label 完全相等时命中，避免 mz/gh 到处误报
ACRONYMS = {
    "gh": ("国惠", "authority"),
    "mz": ("民族", "scam_signature"),
    "yl": ("养老", "policy_theme"),
    "fp": ("扶贫", "policy_theme"),
    "xc": ("乡村", "policy_theme"),
    "zk": ("中科", "authority"),
    "gk": ("国科", "authority"),
}

_MIN_PINYIN_LEN = 4   # 4 个字母以下的拼音词误报太多；配合音节对齐后可放宽到 4
_LABEL_SPLIT = re.compile(r"[-_.]+")
_NON_ALNUM = re.compile(r"[^a-z]")
_ALNUM = re.compile(r"[^a-z0-9]")
_DIGITS = re.compile(r"\d")

# ---------------------------------------------------------------- 音节切分
# 为什么需要它：域名把拼音连写，"minge"（名额）会出现在
# nadinejasmingeissbuehler 这种德语人名里——纯子串匹配必然误报。
# 用 pypinyin 自带的音节表做一次 DP 切分，切不开的 label 直接不做拼音匹配。
_SYLLABLES: frozenset[str] | None = None
_syllable_lock = threading.Lock()


def _syllables() -> frozenset[str]:
    global _SYLLABLES
    if _SYLLABLES is None:
        with _syllable_lock:
            if _SYLLABLES is None:
                from pypinyin.constants import PINYIN_DICT
                from pypinyin.contrib.tone_convert import to_normal

                found: set[str] = set()
                for value in PINYIN_DICT.values():
                    for part in value.split(","):
                        syllable = to_normal(part.strip()).strip()
                        if syllable and syllable.isalpha():
                            found.add(syllable)
                _SYLLABLES = frozenset(found)
    return _SYLLABLES


@lru_cache(maxsize=16384)
def _syllable_bounds(label: str) -> tuple[int, ...] | None:
    """返回音节结束位置的集合；无法完整切分时返回 None。"""
    syllables = _syllables()
    n = len(label)
    if n == 0 or n > 60:
        return None
    ok = [False] * (n + 1)
    prev = [0] * (n + 1)
    ok[0] = True
    for i in range(n):
        if not ok[i]:
            continue
        for j in range(i + 1, min(n, i + 6) + 1):
            if label[i:j] in syllables and not ok[j]:
                ok[j] = True
                prev[j] = i
    if not ok[n]:
        return None
    bounds: list[int] = []
    cur = n
    while cur > 0:
        bounds.append(cur)
        cur = prev[cur]
    return tuple(sorted(bounds))


@dataclass(frozen=True, slots=True)
class Term:
    text: str
    cluster: str
    weight: float
    pinyin: str          # 无分隔的拼音，如 guohuiminsheng 中的 guohui
    weak_only: bool

    @property
    def is_cjk(self) -> bool:
        return bool(self.text) and "\u4e00" <= self.text[0] <= "\u9fff"


@dataclass(slots=True)
class Hit:
    term: str
    cluster: str
    weight: float
    form: str            # cjk | pinyin | acronym
    where: str           # domain | text

    def as_dict(self) -> dict:
        return {"term": self.term, "cluster": self.cluster, "weight": self.weight, "form": self.form}


@dataclass
class MatchResult:
    hits: list[Hit] = field(default_factory=list)
    score: float = 0.0
    clusters: set[str] = field(default_factory=set)

    @property
    def terms(self) -> list[str]:
        seen: list[str] = []
        for h in self.hits:
            if h.term not in seen:
                seen.append(h.term)
        return seen

    def as_dict(self) -> dict:
        return {
            "hits": [h.as_dict() for h in self.hits],
            "score": round(self.score, 3),
            "clusters": sorted(self.clusters),
            "terms": self.terms,
        }


class KeywordLibrary:
    """词库。

    性能约束：CT 流每秒数千张证书、每张多个域名，逐词 in 判断撑不住。
    因此两类匹配都编译成单个正则替择（alternation），交给 re 引擎内部优化。
    实测比逐词循环快 30 倍以上，且代码更短。
    """

    def __init__(self) -> None:
        self.terms: list[Term] = []
        self._by_pinyin: list[Term] = []
        self._pinyin_index: dict[str, Term] = {}
        self._cjk_index: dict[str, Term] = {}
        # 英文词（people / wechat / douyin…）只认整段 label，不做子串：
        # "oceanpeople.org" 不是在冒充人民日报，只是名字里有 people。
        self._ascii_index: dict[str, Term] = {}
        self._build()

    def _build(self) -> None:
        for cluster, spec in CLUSTERS.items():
            base = float(spec["weight"])
            for text in spec["terms"]:
                py = "".join(lazy_pinyin(text))
                py = _NON_ALNUM.sub("", py.lower())
                weight = base * (0.55 if text in WEAK_ONLY else 1.0)
                term = Term(
                    text=text,
                    cluster=cluster,
                    weight=weight,
                    pinyin=py,
                    weak_only=text in WEAK_ONLY,
                )
                self.terms.append(term)
                if py.isalpha() and text.isascii() and len(text) >= 3:
                    self._ascii_index[py] = term
                if len(py) >= _MIN_PINYIN_LEN and py not in self._pinyin_index:
                    self._pinyin_index[py] = term
                    self._by_pinyin.append(term)

        # 长词优先，保证「养老基金」先于「养老」被识别
        self._by_pinyin.sort(key=lambda t: -len(t.pinyin))
        self._cjk_terms = sorted((t for t in self.terms if t.is_cjk), key=lambda t: -len(t.text))
        for t in self._cjk_terms:
            self._cjk_index.setdefault(t.text, t)

        self._pinyin_re = (
            re.compile("|".join(re.escape(t.pinyin) for t in self._by_pinyin), re.IGNORECASE)
            if self._by_pinyin
            else None
        )
        self._cjk_re = (
            re.compile("|".join(re.escape(t.text) for t in self._cjk_terms)) if self._cjk_terms else None
        )

    # ------------------------------------------------------------ 匹配
    def match_text(self, text: str) -> MatchResult:
        """匹配中文语料（标题、页面正文、话术、群名）。"""
        if not text or self._cjk_re is None:
            return MatchResult()
        result = MatchResult()
        seen: set[str] = set()
        for m in self._cjk_re.finditer(text):
            token = m.group(0)
            if token in seen:
                continue
            seen.add(token)
            term = self._cjk_index.get(token)
            if term:
                result.hits.append(Hit(term.text, term.cluster, term.weight, "cjk", "text"))
                result.clusters.add(term.cluster)
        self._finalize(result)
        return result

    def match_domain(self, host: str) -> MatchResult:
        """匹配域名。

        三条通道，精度依次降低、误报依次升高，所以分别设卡：
        - 缩写：整段 label 恰好是缩写（或缩写+不超过 3 位数字，如 mz999）；
        - 英文：整段 label 恰好是英文词（people / douyin / wechat）；
        - 拼音：label 能完整切成音节，且命中正好落在音节边界上。

        早期版本把整串 label 拼起来做子串匹配，22 小时里 2,512 个资产有一半
        是 Snowflake 的随机主机名（-mz11195 / -gk68102）和德语人名（mingeiss），
        纯粹在浪费富化配额。
        """
        if not host:
            return MatchResult()
        host = host.lower().strip(".")
        result = MatchResult()

        labels = [seg for seg in _LABEL_SPLIT.split(host) if seg]
        body = labels[:-1] if len(labels) > 1 else labels
        if not body:
            return result

        for raw_label in body:
            label = _ALNUM.sub("", raw_label)      # 保留数字，用于判断缩写后缀
            alpha = _DIGITS.sub("", label)        # 去数字，用于英文/拼音
            if not alpha:
                continue

            # 1) 缩写：整段就是缩写，或缩写后紧跟不超过 3 位数字（mz999 / gk8）。
            #    机器生成的 mz11195 / gk68102 会被数字位数挡掉。
            if len(alpha) >= 2 and alpha in ACRONYMS:
                suffix = label[len(alpha):]
                if suffix == "" or (suffix.isdigit() and len(suffix) <= 3):
                    text, cluster = ACRONYMS[alpha]
                    weight = CLUSTERS[cluster]["weight"]
                    result.hits.append(Hit(text, cluster, weight, "acronym", "domain"))
                    result.clusters.add(cluster)

            # 2) 英文词：整段相等才算，绝不在长单词里找子串
            term = self._ascii_index.get(alpha)
            if term is not None:
                result.hits.append(Hit(term.text, term.cluster, term.weight, "pinyin", "domain"))
                result.clusters.add(term.cluster)
                continue

            # 3) 拼音：先确认能切成音节，再要求对齐
            self._match_pinyin(alpha, result)

        # 连字符/点分出来的多段，还要拼回去再匹配一次：
        # yanglao-jijin.xyz 这种写法，「养老基金」跨了两个 label。
        # 有了音节对齐，拼回去也不会把随机串拼成词。
        if len(body) > 1:
            self._match_pinyin("".join(_DIGITS.sub("", _ALNUM.sub("", b)) for b in body), result)

        self._finalize(result)
        return result

    def _match_pinyin(self, text: str, result: MatchResult) -> None:
        if not text or self._pinyin_re is None:
            return
        bounds = _syllable_bounds(text)
        if bounds is None:
            return
        starts = {0, *bounds}
        ends = set(bounds)
        for m in self._pinyin_re.finditer(text):
            if m.start() not in starts or m.end() not in ends:
                continue
            term = self._pinyin_index.get(m.group(0).lower())
            if term is None:
                continue
            hit = Hit(term.text, term.cluster, term.weight, "pinyin", "domain")
            if any(h.term == hit.term and h.form == hit.form for h in result.hits):
                continue
            result.hits.append(hit)
            result.clusters.add(term.cluster)

    def match_any(self, host: str = "", text: str = "") -> MatchResult:
        """域名与文本合并判定。文本里出现机构词、域名里出现拼音，都算。"""
        merged = MatchResult()
        if host:
            self._merge(merged, self.match_domain(host))
        if text:
            self._merge(merged, self.match_text(text))
        self._finalize(merged)
        return merged

    # ------------------------------------------------------------ 内部
    @staticmethod
    def _merge(dst: MatchResult, src: MatchResult) -> None:
        seen = {(h.term, h.form) for h in dst.hits}
        for h in src.hits:
            if (h.term, h.form) not in seen:
                dst.hits.append(h)
                seen.add((h.term, h.form))
        dst.clusters |= src.clusters

    @staticmethod
    def _finalize(result: MatchResult) -> None:
        """簇内去重后做 noisy-OR，再按「是否有强簇」压制弱词堆叠。"""
        if not result.hits:
            result.score = 0.0
            return

        # 每个簇只保留最高权重的一条
        best: dict[str, float] = {}
        for h in result.hits:
            best[h.cluster] = max(best.get(h.cluster, 0.0), h.weight)

        # 「强簇」= 冒充机构 / 骗局专属 / 冒用品牌。有其中之一，其余簇才按其原值计入。
        strong = {"scam_signature", "authority", "brand"}
        has_strong = bool(strong & set(best))

        score = 0.0
        for cluster, weight in best.items():
            if cluster in strong:
                pass
            elif cluster == "inducement":
                # 「免费领鸡蛋」单独出现时更像促销而非诈骗，降一档但仍保留可疑性
                weight *= 1.0 if has_strong else 0.55
            elif cluster == "variant":
                # 错别字/谐音是「主动规避关键词审查」的行为，不是无害的相关词。
                # 线上 `butie-fafang.cn`（补帖=补贴）曾因 0.6×0.30=0.18 被直接丢弃。
                weight *= 1.0 if has_strong else 0.75
            elif cluster == "policy_theme":
                # 政策词单独出现只说明「相关」，但域名里写「扶贫/养老/补贴」的
                # 极少是无辜站点。折算压到 0.30 会让这类域名（0.55×0.30=0.165）
                # 连 0.30 的落库门槛都过不去——最该盯的一类反而全被丢掉。
                weight *= 1.0 if has_strong else 0.55
            else:
                # 纯政策词 / 载体词，没有强簇支撑时只是「相关」，不是「可疑」
                weight *= 0.70 if has_strong else 0.30
            score = 1 - (1 - score) * (1 - min(weight, 0.99))

        result.score = min(score, 0.99)

    # ------------------------------------------------------------ 白名单
    @staticmethod
    def is_whitelisted(host: str) -> bool:
        host = host.lower().strip(".")
        if not host:
            return False
        if host in WHITELIST_DOMAINS:
            return True
        if any(host.endswith(suffix) for suffix in WHITELIST_SUFFIXES):
            return True
        # 子域也放行：www.gov.cn 之类
        parts = host.split(".")
        for i in range(1, len(parts)):
            if ".".join(parts[i:]) in WHITELIST_DOMAINS:
                return True
        return False

    # ------------------------------------------------------------ 统计
    def stats(self) -> dict:
        by_cluster: dict[str, int] = {}
        for t in self.terms:
            by_cluster[t.cluster] = by_cluster.get(t.cluster, 0) + 1
        return {
            "terms": len(self.terms),
            "pinyin_terms": len(self._by_pinyin),
            "by_cluster": by_cluster,
        }


@lru_cache(maxsize=1)
def get_library() -> KeywordLibrary:
    return KeywordLibrary()
