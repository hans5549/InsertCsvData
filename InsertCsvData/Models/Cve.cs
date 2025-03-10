using Newtonsoft.Json;

namespace InsertCsvData.Models;

public class Cve
{
    /// <summary>
    /// 根物件，表示完整的 CVE 記錄
    /// </summary>
    public class CveRecord
    {
        /// <summary>
        /// 資料類型，例如 "CVE_RECORD"
        /// </summary>
        [JsonProperty("dataType")]
        public string DataType { get; set; } = string.Empty;

        /// <summary>
        /// 資料版本，例如 "5.1"
        /// </summary>
        [JsonProperty("dataVersion")]
        public string DataVersion { get; set; } = string.Empty;

        /// <summary>
        /// CVE 元資料
        /// </summary>
        [JsonProperty("cveMetadata")]
        public CveMetadata CveMetadata { get; set; }

        /// <summary>
        /// 容器資料，包含 CNA 和 ADP 資訊
        /// </summary>
        [JsonProperty("containers")]
        public Containers Containers { get; set; }
    }

    /// <summary>
    /// CVE 元資料
    /// </summary>
    public class CveMetadata
    {
        /// <summary>
        /// CVE 編號，例如 "CVE-2025-0001"
        /// </summary>
        [JsonProperty("cveId")]
        public string CveId { get; set; } = string.Empty;

        /// <summary>
        /// 分配組織的 ID
        /// </summary>
        [JsonProperty("assignerOrgId")]
        public string AssignerOrgId { get; set; } = string.Empty;

        /// <summary>
        /// 分配組織簡稱，例如 "sap"
        /// </summary>
        [JsonProperty("assignerShortName")]
        public string AssignerShortName { get; set; } = string.Empty;

        /// <summary>
        /// 請求者用戶 ID
        /// </summary>
        [JsonProperty("requesterUserId")]
        public string RequesterUserId { get; set; } = string.Empty;

        /// <summary>
        /// 序列號
        /// </summary>
        [JsonProperty("serial")]
        public int? Serial { get; set; }

        /// <summary>
        /// 狀態，例如 "PUBLISHED"
        /// </summary>
        [JsonProperty("state")]
        public string State { get; set; } = string.Empty;

        /// <summary>
        /// 保留日期
        /// </summary>
        [JsonProperty("dateReserved")]
        public DateTime? DateReserved { get; set; }

        /// <summary>
        /// 發布日期
        /// </summary>
        [JsonProperty("datePublished")]
        public DateTime? DatePublished { get; set; }

        /// <summary>
        /// 更新日期
        /// </summary>
        [JsonProperty("dateUpdated")]
        public DateTime? DateUpdated { get; set; }
    }

    /// <summary>
    /// 容器資料
    /// </summary>
    public class Containers
    {
        /// <summary>
        /// CNA (CVE Numbering Authority) 資料
        /// </summary>
        [JsonProperty("cna")]
        public Cna Cna { get; set; }

        /// <summary>
        /// ADP (Additional Data Provider) 資料
        /// </summary>
        [JsonProperty("adp")]
        public List<Adp> Adp { get; set; }
    }

    /// <summary>
    /// CNA 資料
    /// </summary>
    public class Cna
    {
        /// <summary>
        /// 提供者元資料
        /// </summary>
        [JsonProperty("providerMetadata")]
        public ProviderMetadata ProviderMetadata { get; set; }

        /// <summary>
        /// 漏洞標題
        /// </summary>
        [JsonProperty("title")]
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// 公開日期
        /// </summary>
        [JsonProperty("datePublic")]
        public DateTime? DatePublic { get; set; }

        /// <summary>
        /// 問題類型列表
        /// </summary>
        [JsonProperty("problemTypes")]
        public List<ProblemType> ProblemTypes { get; set; }

        /// <summary>
        /// 影響列表
        /// </summary>
        [JsonProperty("impacts")]
        public List<Impact> Impacts { get; set; }

        /// <summary>
        /// 受影響的產品資訊
        /// </summary>
        [JsonProperty("affected")]
        public List<Affected> Affected { get; set; }

        /// <summary>
        /// 漏洞描述列表
        /// </summary>
        [JsonProperty("descriptions")]
        public List<Description> Descriptions { get; set; }

        /// <summary>
        /// 漏洞評分指標
        /// </summary>
        [JsonProperty("metrics")]
        public List<Metric> Metrics { get; set; }

        /// <summary>
        /// 解決方案列表
        /// </summary>
        [JsonProperty("solutions")]
        public List<Solution> Solutions { get; set; }

        /// <summary>
        /// 臨時解決方法列表
        /// </summary>
        [JsonProperty("workarounds")]
        public List<Workaround> Workarounds { get; set; }

        /// <summary>
        /// 參考資料列表
        /// </summary>
        [JsonProperty("references")]
        public List<Reference> References { get; set; }

        /// <summary>
        /// 來源資訊
        /// </summary>
        [JsonProperty("source")]
        public Source Source { get; set; }

        /// <summary>
        /// 貢獻者資訊
        /// </summary>
        [JsonProperty("credits")]
        public List<Credit> Credits { get; set; }

        /// <summary>
        /// 配置資訊
        /// </summary>
        [JsonProperty("configurations")]
        public List<Configuration> Configurations { get; set; }

        /// <summary>
        /// 時間線
        /// </summary>
        [JsonProperty("timeline")]
        public List<Timeline> Timeline { get; set; }

        /// <summary>
        /// 產生器資訊
        /// </summary>
        [JsonProperty("x_generator")]
        public Generator Generator { get; set; }

        /// <summary>
        /// 標籤
        /// </summary>
        [JsonProperty("tags")]
        public List<string> Tags { get; set; }

        /// <summary>
        /// 受影響的版本列表
        /// </summary>
        [JsonProperty("x_affectedList")]
        public List<string> XAffectedList { get; set; }

        /// <summary>
        /// 模組
        /// </summary>
        [JsonProperty("modules")]
        public List<string> Modules { get; set; }
    }

    /// <summary>
    /// ADP 資料
    /// </summary>
    public class Adp
    {
        /// <summary>
        /// 評分指標
        /// </summary>
        [JsonProperty("metrics")]
        public List<AdpMetric> Metrics { get; set; }

        /// <summary>
        /// 標題
        /// </summary>
        [JsonProperty("title")]
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// 提供者元資料
        /// </summary>
        [JsonProperty("providerMetadata")]
        public ProviderMetadata ProviderMetadata { get; set; }

        /// <summary>
        /// 參考資料
        /// </summary>
        [JsonProperty("references")]
        public List<Reference> References { get; set; }

        /// <summary>
        /// 時間線
        /// </summary>
        [JsonProperty("timeline")]
        public List<Timeline> Timeline { get; set; }
    }

    /// <summary>
    /// 受影響的產品資訊
    /// </summary>
    public class Affected
    {
        /// <summary>
        /// 廠商名稱，例如 "Example.org"
        /// </summary>
        [JsonProperty("vendor")]
        public string Vendor { get; set; }

        /// <summary>
        /// 產品名稱，例如 "Example Enterprise"
        /// </summary>
        [JsonProperty("product")]
        public string Product { get; set; }

        /// <summary>
        /// 支援平台，例如 ["Windows", "MacOS", "XT-4500"]
        /// </summary>
        [JsonProperty("platforms")]
        public List<string> Platforms { get; set; }

        /// <summary>
        /// 版本資訊列表
        /// </summary>
        [JsonProperty("versions")]
        public List<Version> Versions { get; set; }

        /// <summary>
        /// 預設狀態，例如 "unaffected"
        /// </summary>
        [JsonProperty("defaultStatus")]
        public string DefaultStatus { get; set; }

        /// <summary>
        /// CPE 識別碼列表
        /// </summary>
        [JsonProperty("cpes")]
        public List<string> Cpes { get; set; }

        /// <summary>
        /// 儲存庫
        /// </summary>
        [JsonProperty("repo")]
        public string Repo { get; set; }

        /// <summary>
        /// 模組
        /// </summary>
        [JsonProperty("modules")]
        public List<string> Modules { get; set; }
    }

    /// <summary>
    /// 版本資訊
    /// </summary>
    public class Version
    {
        /// <summary>
        /// 版本號，例如 "1.0.0"
        /// </summary>
        [JsonProperty("version")]
        public string VersionNumber { get; set; }

        /// <summary>
        /// 狀態，例如 "affected" 或 "unaffected"
        /// </summary>
        [JsonProperty("status")]
        public string Status { get; set; }

        /// <summary>
        /// 小於某版本，例如 "1.0.6"
        /// </summary>
        [JsonProperty("lessThan")]
        public string LessThan { get; set; }

        /// <summary>
        /// 小於等於某版本
        /// </summary>
        [JsonProperty("lessThanOrEqual")]
        public string LessThanOrEqual { get; set; }

        /// <summary>
        /// 版本類型，例如 "semver", "custom"
        /// </summary>
        [JsonProperty("versionType")]
        public string VersionType { get; set; }

        /// <summary>
        /// 版本變更列表
        /// </summary>
        [JsonProperty("changes")]
        public List<Change> Changes { get; set; }
    }

    /// <summary>
    /// 版本變更
    /// </summary>
    public class Change
    {
        /// <summary>
        /// 變更版本點，例如 "1.2.0"
        /// </summary>
        [JsonProperty("at")]
        public string At { get; set; }

        /// <summary>
        /// 變更後的狀態，例如 "unaffected"
        /// </summary>
        [JsonProperty("status")]
        public string Status { get; set; }
    }

    /// <summary>
    /// 漏洞評分指標
    /// </summary>
    public class Metric
    {
        /// <summary>
        /// 評分格式，例如 "CVSS"
        /// </summary>
        [JsonProperty("format")]
        public string Format { get; set; }

        /// <summary>
        /// CVSS 3.1 評分
        /// </summary>
        [JsonProperty("cvssV3_1")]
        public CvssV31 CvssV31 { get; set; }

        /// <summary>
        /// CVSS 4.0 評分
        /// </summary>
        [JsonProperty("cvssV4_0")]
        public CvssV40 CvssV40 { get; set; }

        /// <summary>
        /// CVSS 3.0 評分
        /// </summary>
        [JsonProperty("cvssV3_0")]
        public CvssV30 CvssV30 { get; set; }

        /// <summary>
        /// CVSS 2.0 評分
        /// </summary>
        [JsonProperty("cvssV2_0")]
        public CvssV20 CvssV20 { get; set; }

        /// <summary>
        /// 評分場景
        /// </summary>
        [JsonProperty("scenarios")]
        public List<Scenario> Scenarios { get; set; }
    }

    /// <summary>
    /// ADP 評分指標
    /// </summary>
    public class AdpMetric
    {
        /// <summary>
        /// CVSS 3.1 評分
        /// </summary>
        [JsonProperty("cvssV3_1")]
        public CvssV31 CvssV31 { get; set; }

        /// <summary>
        /// 其他評分系統
        /// </summary>
        [JsonProperty("other")]
        public OtherMetric Other { get; set; }
    }

    /// <summary>
    /// 其他評分系統
    /// </summary>
    public class OtherMetric
    {
        /// <summary>
        /// 評分類型，例如 "ssvc"
        /// </summary>
        [JsonProperty("type")]
        public string Type { get; set; }

        /// <summary>
        /// 評分內容
        /// </summary>
        [JsonProperty("content")]
        public object Content { get; set; }
    }

    /// <summary>
    /// CVSS 評分 (3.1 版)
    /// </summary>
    public class CvssV31
    {
        /// <summary>
        /// 版本，例如 "3.1"
        /// </summary>
        [JsonProperty("version")]
        public string Version { get; set; }

        /// <summary>
        /// 基礎分數，例如 9.8
        /// </summary>
        [JsonProperty("baseScore")]
        public float BaseScore { get; set; }

        /// <summary>
        /// 嚴重性，例如 "CRITICAL"
        /// </summary>
        [JsonProperty("baseSeverity")]
        public string BaseSeverity { get; set; }

        /// <summary>
        /// 向量字串
        /// </summary>
        [JsonProperty("vectorString")]
        public string VectorString { get; set; }

        /// <summary>
        /// 攻擊向量
        /// </summary>
        [JsonProperty("attackVector")]
        public string AttackVector { get; set; }

        /// <summary>
        /// 攻擊複雜度
        /// </summary>
        [JsonProperty("attackComplexity")]
        public string AttackComplexity { get; set; }

        /// <summary>
        /// 所需權限
        /// </summary>
        [JsonProperty("privilegesRequired")]
        public string PrivilegesRequired { get; set; }

        /// <summary>
        /// 用戶互動
        /// </summary>
        [JsonProperty("userInteraction")]
        public string UserInteraction { get; set; }

        /// <summary>
        /// 影響範圍
        /// </summary>
        [JsonProperty("scope")]
        public string Scope { get; set; }

        /// <summary>
        /// 機密性影響
        /// </summary>
        [JsonProperty("confidentialityImpact")]
        public string ConfidentialityImpact { get; set; }

        /// <summary>
        /// 完整性影響
        /// </summary>
        [JsonProperty("integrityImpact")]
        public string IntegrityImpact { get; set; }

        /// <summary>
        /// 可用性影響
        /// </summary>
        [JsonProperty("availabilityImpact")]
        public string AvailabilityImpact { get; set; }
    }

    /// <summary>
    /// CVSS 評分 (3.0 版)
    /// </summary>
    public class CvssV30
    {
        /// <summary>
        /// 版本，例如 "3.0"
        /// </summary>
        [JsonProperty("version")]
        public string Version { get; set; }

        /// <summary>
        /// 基礎分數
        /// </summary>
        [JsonProperty("baseScore")]
        public float BaseScore { get; set; }

        /// <summary>
        /// 嚴重性
        /// </summary>
        [JsonProperty("baseSeverity")]
        public string BaseSeverity { get; set; }

        /// <summary>
        /// 向量字串
        /// </summary>
        [JsonProperty("vectorString")]
        public string VectorString { get; set; }
    }

    /// <summary>
    /// CVSS 評分 (2.0 版)
    /// </summary>
    public class CvssV20
    {
        /// <summary>
        /// 版本，例如 "2.0"
        /// </summary>
        [JsonProperty("version")]
        public string Version { get; set; }

        /// <summary>
        /// 基礎分數
        /// </summary>
        [JsonProperty("baseScore")]
        public float BaseScore { get; set; }

        /// <summary>
        /// 向量字串
        /// </summary>
        [JsonProperty("vectorString")]
        public string VectorString { get; set; }
    }

    /// <summary>
    /// CVSS 評分 (4.0 版)
    /// </summary>
    public class CvssV40
    {
        /// <summary>
        /// 版本，例如 "4.0"
        /// </summary>
        [JsonProperty("version")]
        public string Version { get; set; }

        /// <summary>
        /// 基礎分數，例如 7.8
        /// </summary>
        [JsonProperty("baseScore")]
        public float BaseScore { get; set; }

        /// <summary>
        /// 嚴重性，例如 "HIGH"
        /// </summary>
        [JsonProperty("baseSeverity")]
        public string BaseSeverity { get; set; }

        /// <summary>
        /// 向量字串
        /// </summary>
        [JsonProperty("vectorString")]
        public string VectorString { get; set; }

        /// <summary>
        /// 攻擊向量
        /// </summary>
        [JsonProperty("attackVector")]
        public string AttackVector { get; set; }

        /// <summary>
        /// 攻擊複雜度
        /// </summary>
        [JsonProperty("attackComplexity")]
        public string AttackComplexity { get; set; }

        /// <summary>
        /// 攻擊需求
        /// </summary>
        [JsonProperty("attackRequirements")]
        public string AttackRequirements { get; set; }

        /// <summary>
        /// 所需權限
        /// </summary>
        [JsonProperty("privilegesRequired")]
        public string PrivilegesRequired { get; set; }

        /// <summary>
        /// 用戶互動
        /// </summary>
        [JsonProperty("userInteraction")]
        public string UserInteraction { get; set; }

        /// <summary>
        /// 提供者緊急程度
        /// </summary>
        [JsonProperty("providerUrgency")]
        public string ProviderUrgency { get; set; }

        /// <summary>
        /// 是否可自動化
        /// </summary>
        [JsonProperty("Automatable")]
        public string Automatable { get; set; }

        /// <summary>
        /// 復原
        /// </summary>
        [JsonProperty("Recovery")]
        public string Recovery { get; set; }

        /// <summary>
        /// 安全性
        /// </summary>
        [JsonProperty("Safety")]
        public string Safety { get; set; }

        /// <summary>
        /// 漏洞可用性影響
        /// </summary>
        [JsonProperty("vulnAvailabilityImpact")]
        public string VulnAvailabilityImpact { get; set; }

        /// <summary>
        /// 漏洞機密性影響
        /// </summary>
        [JsonProperty("vulnConfidentialityImpact")]
        public string VulnConfidentialityImpact { get; set; }

        /// <summary>
        /// 漏洞完整性影響
        /// </summary>
        [JsonProperty("vulnIntegrityImpact")]
        public string VulnIntegrityImpact { get; set; }

        /// <summary>
        /// 漏洞應對努力
        /// </summary>
        [JsonProperty("vulnerabilityResponseEffort")]
        public string VulnerabilityResponseEffort { get; set; }

        /// <summary>
        /// 價值密度
        /// </summary>
        [JsonProperty("valueDensity")]
        public string ValueDensity { get; set; }

        /// <summary>
        /// 子可用性影響
        /// </summary>
        [JsonProperty("subAvailabilityImpact")]
        public string SubAvailabilityImpact { get; set; }

        /// <summary>
        /// 子機密性影響
        /// </summary>
        [JsonProperty("subConfidentialityImpact")]
        public string SubConfidentialityImpact { get; set; }

        /// <summary>
        /// 子完整性影響
        /// </summary>
        [JsonProperty("subIntegrityImpact")]
        public string SubIntegrityImpact { get; set; }
    }

    /// <summary>
    /// 提供者元資料
    /// </summary>
    public class ProviderMetadata
    {
        /// <summary>
        /// 組織 ID
        /// </summary>
        [JsonProperty("orgId")]
        public string OrgId { get; set; }

        /// <summary>
        /// 簡稱
        /// </summary>
        [JsonProperty("shortName")]
        public string ShortName { get; set; }

        /// <summary>
        /// 更新日期
        /// </summary>
        [JsonProperty("dateUpdated")]
        public DateTime? DateUpdated { get; set; }
    }

    /// <summary>
    /// 問題類型
    /// </summary>
    public class ProblemType
    {
        /// <summary>
        /// 描述列表
        /// </summary>
        [JsonProperty("descriptions")]
        public List<ProblemTypeDescription> Descriptions { get; set; }
    }

    /// <summary>
    /// 問題類型描述
    /// </summary>
    public class ProblemTypeDescription
    {
        /// <summary>
        /// 語言
        /// </summary>
        [JsonProperty("lang")]
        public string Lang { get; set; }

        /// <summary>
        /// 描述
        /// </summary>
        [JsonProperty("description")]
        public string Description { get; set; }

        /// <summary>
        /// CWE ID
        /// </summary>
        [JsonProperty("cweId")]
        public string CweId { get; set; }

        /// <summary>
        /// 類型
        /// </summary>
        [JsonProperty("type")]
        public string Type { get; set; }
    }

    /// <summary>
    /// 影響
    /// </summary>
    public class Impact
    {
        /// <summary>
        /// CAPEC ID
        /// </summary>
        [JsonProperty("capecId")]
        public string CapecId { get; set; }

        /// <summary>
        /// 描述列表
        /// </summary>
        [JsonProperty("descriptions")]
        public List<ImpactDescription> Descriptions { get; set; }
    }

    /// <summary>
    /// 影響描述
    /// </summary>
    public class ImpactDescription
    {
        /// <summary>
        /// 語言
        /// </summary>
        [JsonProperty("lang")]
        public string Lang { get; set; }

        /// <summary>
        /// 描述內容
        /// </summary>
        [JsonProperty("value")]
        public string Value { get; set; }
    }

    /// <summary>
    /// 漏洞描述
    /// </summary>
    public class Description
    {
        /// <summary>
        /// 語言
        /// </summary>
        [JsonProperty("lang")]
        public string Lang { get; set; }

        /// <summary>
        /// 描述內容
        /// </summary>
        [JsonProperty("value")]
        public string Value { get; set; }

        /// <summary>
        /// 支援媒體
        /// </summary>
        [JsonProperty("supportingMedia")]
        public List<SupportingMedia> SupportingMedia { get; set; }
    }

    /// <summary>
    /// 支援媒體
    /// </summary>
    public class SupportingMedia
    {
        /// <summary>
        /// 是否為 Base64 編碼
        /// </summary>
        [JsonProperty("base64")]
        public bool Base64 { get; set; }

        /// <summary>
        /// 媒體類型
        /// </summary>
        [JsonProperty("type")]
        public string Type { get; set; }

        /// <summary>
        /// 媒體內容
        /// </summary>
        [JsonProperty("value")]
        public string Value { get; set; }
    }

    /// <summary>
    /// 評分場景
    /// </summary>
    public class Scenario
    {
        /// <summary>
        /// 語言
        /// </summary>
        [JsonProperty("lang")]
        public string Lang { get; set; }

        /// <summary>
        /// 場景值
        /// </summary>
        [JsonProperty("value")]
        public string Value { get; set; }
    }

    /// <summary>
    /// 解決方案
    /// </summary>
    public class Solution
    {
        /// <summary>
        /// 語言
        /// </summary>
        [JsonProperty("lang")]
        public string Lang { get; set; }

        /// <summary>
        /// 解決方案內容
        /// </summary>
        [JsonProperty("value")]
        public string Value { get; set; }

        /// <summary>
        /// 支援媒體
        /// </summary>
        [JsonProperty("supportingMedia")]
        public List<SupportingMedia> SupportingMedia { get; set; }
    }

    /// <summary>
    /// 臨時解決方法
    /// </summary>
    public class Workaround
    {
        /// <summary>
        /// 語言
        /// </summary>
        [JsonProperty("lang")]
        public string Lang { get; set; }

        /// <summary>
        /// 解決方法內容
        /// </summary>
        [JsonProperty("value")]
        public string Value { get; set; }

        /// <summary>
        /// 支援媒體
        /// </summary>
        [JsonProperty("supportingMedia")]
        public List<SupportingMedia> SupportingMedia { get; set; }
    }

    /// <summary>
    /// 參考資料
    /// </summary>
    public class Reference
    {
        public Reference(string url)
        {
            Url = url;
        }

        /// <summary>
        /// URL
        /// </summary>
        [JsonProperty("url")]
        public string Url { get; set; }

        /// <summary>
        /// 名稱
        /// </summary>
        [JsonProperty("name")]
        public string Name { get; set; }

        /// <summary>
        /// 標籤
        /// </summary>
        [JsonProperty("tags")]
        public List<string> Tags { get; set; }
    }

    /// <summary>
    /// 來源資訊
    /// </summary>
    public class Source
    {
        /// <summary>
        /// 發現方式
        /// </summary>
        [JsonProperty("discovery")]
        public string Discovery { get; set; }

        /// <summary>
        /// 公告
        /// </summary>
        [JsonProperty("advisory")]
        public string Advisory { get; set; }
    }

    /// <summary>
    /// 貢獻者資訊
    /// </summary>
    public class Credit
    {
        /// <summary>
        /// 語言
        /// </summary>
        [JsonProperty("lang")]
        public string Lang { get; set; }

        /// <summary>
        /// 貢獻者名稱
        /// </summary>
        [JsonProperty("value")]
        public string Value { get; set; }

        /// <summary>
        /// 貢獻類型
        /// </summary>
        [JsonProperty("type")]
        public string Type { get; set; }
    }

    /// <summary>
    /// 配置資訊
    /// </summary>
    public class Configuration
    {
        /// <summary>
        /// 語言
        /// </summary>
        [JsonProperty("lang")]
        public string Lang { get; set; }

        /// <summary>
        /// 配置內容
        /// </summary>
        [JsonProperty("value")]
        public string Value { get; set; }
    }

    /// <summary>
    /// 時間線
    /// </summary>
    public class Timeline
    {
        /// <summary>
        /// 時間
        /// </summary>
        [JsonProperty("time")]
        public DateTime? Time { get; set; }

        /// <summary>
        /// 語言
        /// </summary>
        [JsonProperty("lang")]
        public string Lang { get; set; }

        /// <summary>
        /// 事件描述
        /// </summary>
        [JsonProperty("value")]
        public string Value { get; set; }
    }

    /// <summary>
    /// 產生器資訊
    /// </summary>
    public class Generator
    {
        /// <summary>
        /// 引擎
        /// </summary>
        [JsonProperty("engine")]
        public string Engine { get; set; }

        /// <summary>
        /// 日期
        /// </summary>
        [JsonProperty("date")]
        public DateTime? Date { get; set; }
    }
}