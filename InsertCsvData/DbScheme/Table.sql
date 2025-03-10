-- CVE 記錄主表
CREATE TABLE CveRecords
(
    Id                INT IDENTITY(1,1) PRIMARY KEY,
    DataType          NVARCHAR(50),
    DataVersion       NVARCHAR(20),
    -- CveMetadata
    CveId             NVARCHAR(20),
    AssignerOrgId     NVARCHAR(100),
    AssignerShortName NVARCHAR(50),
    RequesterUserId   NVARCHAR(100),
    Serial            INT,
    State             NVARCHAR(50),
    DateReserved      DATETIME,
    DatePublished     DATETIME,
    DateUpdated       DATETIME
);

-- CNA 資料表
CREATE TABLE CnaDatas
(
    Id                  INT IDENTITY(1,1) PRIMARY KEY,
    CveRecordId         INT,
    Title               NVARCHAR(500),
    DatePublic          DATETIME,
    -- Source
    SourceDiscovery     NVARCHAR(100),
    SourceAdvisory      NVARCHAR(100),
    -- ProviderMetadata
    ProviderOrgId       NVARCHAR(100),
    ProviderShortName   NVARCHAR(50),
    ProviderDateUpdated DATETIME,
    -- Generator
    GeneratorEngine     NVARCHAR(100),
    GeneratorDate       DATETIME
);

-- ADP 資料表
CREATE TABLE AdpDatas
(
    Id                  INT IDENTITY(1,1) PRIMARY KEY,
    CveRecordId         INT,
    Title               NVARCHAR(500),
    -- ProviderMetadata
    ProviderOrgId       NVARCHAR(100),
    ProviderShortName   NVARCHAR(50),
    ProviderDateUpdated DATETIME
);

-- 問題類型表
CREATE TABLE ProblemTypes
(
    Id          INT IDENTITY(1,1) PRIMARY KEY,
    CnaId       INT,
    Lang        NVARCHAR(10),
    Description NVARCHAR(MAX),
    CweId       NVARCHAR(20),
    Type        NVARCHAR(50)
);

-- 影響表
CREATE TABLE Impacts
(
    Id      INT IDENTITY(1,1) PRIMARY KEY,
    CnaId   INT,
    CapecId NVARCHAR(20),
    Lang    NVARCHAR(10),
    Value   NVARCHAR(MAX)
);

-- 受影響產品表
CREATE TABLE AffectedProducts
(
    Id            INT IDENTITY(1,1) PRIMARY KEY,
    CnaId         INT,
    Vendor        NVARCHAR(200),
    Product       NVARCHAR(200),
    DefaultStatus NVARCHAR(50),
    Repo          NVARCHAR(255)
);

-- 平台表
CREATE TABLE Platforms
(
    Id                INT IDENTITY(1,1) PRIMARY KEY,
    AffectedProductId INT,
    PlatformName      NVARCHAR(100)
);

-- CPE 識別碼表
CREATE TABLE Cpes
(
    Id                INT IDENTITY(1,1) PRIMARY KEY,
    AffectedProductId INT,
    CpeValue          NVARCHAR(255)
);

-- 模組表
CREATE TABLE Modules
(
    Id                INT IDENTITY(1,1) PRIMARY KEY,
    AffectedProductId INT,
    ModuleName        NVARCHAR(200)
);

-- 版本表
CREATE TABLE Versions
(
    Id                INT IDENTITY(1,1) PRIMARY KEY,
    AffectedProductId INT,
    VersionNumber     NVARCHAR(100),
    Status            NVARCHAR(50),
    LessThan          NVARCHAR(100),
    LessThanOrEqual   NVARCHAR(100),
    VersionType       NVARCHAR(50)
);

-- 版本變更表
CREATE TABLE VersionChanges
(
    Id        INT IDENTITY(1,1) PRIMARY KEY,
    VersionId INT,
    At        NVARCHAR(100),
    Status    NVARCHAR(50)
);

-- 描述表
CREATE TABLE Descriptions
(
    Id    INT IDENTITY(1,1) PRIMARY KEY,
    CnaId INT,
    Lang  NVARCHAR(10),
    Value NVARCHAR(MAX)
);

-- 支援媒體表
CREATE TABLE SupportingMedias
(
    Id         INT IDENTITY(1,1) PRIMARY KEY,
    ParentId   INT,
    ParentType NVARCHAR(50), -- 'Description', 'Solution', 'Workaround'
    Base64     BIT,
    MediaType  NVARCHAR(100),
    Value      NVARCHAR(MAX)
);

-- 評分指標表
CREATE TABLE Metrics
(
    Id     INT IDENTITY(1,1) PRIMARY KEY,
    CnaId  INT,
    Format NVARCHAR(20)
);

-- CVSS 3.1 評分表
CREATE TABLE CvssV31
(
    Id                    INT IDENTITY(1,1) PRIMARY KEY,
    MetricId              INT,
    Version               NVARCHAR(10),
    BaseScore             FLOAT,
    BaseSeverity          NVARCHAR(20),
    VectorString          NVARCHAR(MAX),
    AttackVector          NVARCHAR(50),
    AttackComplexity      NVARCHAR(50),
    PrivilegesRequired    NVARCHAR(50),
    UserInteraction       NVARCHAR(50),
    Scope                 NVARCHAR(50),
    ConfidentialityImpact NVARCHAR(50),
    IntegrityImpact       NVARCHAR(50),
    AvailabilityImpact    NVARCHAR(50)
);

-- CVSS 4.0 評分表
CREATE TABLE CvssV40
(
    Id                          INT IDENTITY(1,1) PRIMARY KEY,
    MetricId                    INT,
    Version                     NVARCHAR(10),
    BaseScore                   FLOAT,
    BaseSeverity                NVARCHAR(20),
    VectorString                NVARCHAR(MAX),
    AttackVector                NVARCHAR(50),
    AttackComplexity            NVARCHAR(50),
    AttackRequirements          NVARCHAR(50),
    PrivilegesRequired          NVARCHAR(50),
    UserInteraction             NVARCHAR(50),
    ProviderUrgency             NVARCHAR(50),
    Automatable                 NVARCHAR(50),
    Recovery                    NVARCHAR(50),
    Safety                      NVARCHAR(50),
    VulnAvailabilityImpact      NVARCHAR(50),
    VulnConfidentialityImpact   NVARCHAR(50),
    VulnIntegrityImpact         NVARCHAR(50),
    VulnerabilityResponseEffort NVARCHAR(50),
    ValueDensity                NVARCHAR(50),
    SubAvailabilityImpact       NVARCHAR(50),
    SubConfidentialityImpact    NVARCHAR(50),
    SubIntegrityImpact          NVARCHAR(50)
);

-- CVSS 3.0 評分表
CREATE TABLE CvssV30
(
    Id           INT IDENTITY(1,1) PRIMARY KEY,
    MetricId     INT,
    Version      NVARCHAR(10),
    BaseScore    FLOAT,
    BaseSeverity NVARCHAR(20),
    VectorString NVARCHAR(MAX)
);

-- CVSS 2.0 評分表
CREATE TABLE CvssV20
(
    Id           INT IDENTITY(1,1) PRIMARY KEY,
    MetricId     INT,
    Version      NVARCHAR(10),
    BaseScore    FLOAT,
    VectorString NVARCHAR(MAX)
);

-- ADP 評分表
CREATE TABLE AdpMetrics
(
    Id           INT IDENTITY(1,1) PRIMARY KEY,
    AdpId        INT,
    OtherType    NVARCHAR(50),
    OtherContent NVARCHAR(MAX)
);

-- 評分場景表
CREATE TABLE Scenarios
(
    Id       INT IDENTITY(1,1) PRIMARY KEY,
    MetricId INT,
    Lang     NVARCHAR(10),
    Value    NVARCHAR(MAX)
);

-- 解決方案表
CREATE TABLE Solutions
(
    Id    INT IDENTITY(1,1) PRIMARY KEY,
    CnaId INT,
    Lang  NVARCHAR(10),
    Value NVARCHAR(MAX)
);

-- 臨時解決方法表
CREATE TABLE Workarounds
(
    Id    INT IDENTITY(1,1) PRIMARY KEY,
    CnaId INT,
    Lang  NVARCHAR(10),
    Value NVARCHAR(MAX)
);

-- 參考資料表
CREATE TABLE References
(
    Id         INT IDENTITY(1,1) PRIMARY KEY,
    ParentId   INT,
    ParentType NVARCHAR(20), -- 'Cna', 'Adp'
    Url        NVARCHAR(500),
    Name       NVARCHAR(200)
);

-- 參考資料標籤表
CREATE TABLE ReferenceTags
(
    Id          INT IDENTITY(1,1) PRIMARY KEY,
    ReferenceId INT,
    Tag         NVARCHAR(100)
);

-- 貢獻者表
CREATE TABLE Credits
(
    Id    INT IDENTITY(1,1) PRIMARY KEY,
    CnaId INT,
    Lang  NVARCHAR(10),
    Value NVARCHAR(MAX),
    Type  NVARCHAR(50)
);

-- 配置表
CREATE TABLE Configurations
(
    Id    INT IDENTITY(1,1) PRIMARY KEY,
    CnaId INT,
    Lang  NVARCHAR(10),
    Value NVARCHAR(MAX)
);

-- 時間線表
CREATE TABLE Timelines
(
    Id         INT IDENTITY(1,1) PRIMARY KEY,
    ParentId   INT,
    ParentType NVARCHAR(20), -- 'Cna', 'Adp'
    Time       DATETIME,
    Lang       NVARCHAR(10),
    Value      NVARCHAR(MAX)
);

-- 標籤表
CREATE TABLE Tags
(
    Id    INT IDENTITY(1,1) PRIMARY KEY,
    CnaId INT,
    Tag   NVARCHAR(100)
);

-- 受影響版本列表
CREATE TABLE XAffectedList
(
    Id            INT IDENTITY(1,1) PRIMARY KEY,
    CnaId         INT,
    AffectedValue NVARCHAR(200)
);
