-- CVE 記錄的主要資訊
CREATE TABLE CveRecord
(
    Id                INT IDENTITY(1,1) PRIMARY KEY,
    CveId             NVARCHAR(20) NOT NULL,
    Title             NVARCHAR(500),
    DatePublished     DATETIME,
    DateReserved      DATETIME,
    DateUpdated       DATETIME,
    DatePublic        DATETIME,
    DateRejected      DATETIME,
    AssignerOrgId     NVARCHAR(100),
    AssignerShortName NVARCHAR(100),
    State             NVARCHAR(50),
    Discovery         NVARCHAR(100),
    CONSTRAINT UQ_CveRecord_CveId UNIQUE (CveId)
);
CREATE INDEX IX_CveRecord_CveId ON CveRecord (CveId);

-- 受影響的產品資訊
CREATE TABLE CveAffectedProduct
(
    Id            INT IDENTITY(1,1) PRIMARY KEY,
    CveId         NVARCHAR(20) NOT NULL,
    Vendor        NVARCHAR(200),
    Product       NVARCHAR(200),
    DefaultStatus NVARCHAR(50),
    Repo          NVARCHAR(500),
    CollectionUrl NVARCHAR(500),
    PackageName   NVARCHAR(200)
);
CREATE INDEX IX_CveAffectedProduct_CveId ON CveAffectedProduct (CveId);
CREATE INDEX IX_CveAffectedProduct_Product ON CveAffectedProduct (Product);

-- 產品的 CPE 資訊
CREATE TABLE CveProductCpe
(
    Id      INT IDENTITY(1,1) PRIMARY KEY,
    CveId   NVARCHAR(20) NOT NULL,
    Product NVARCHAR(200),
    Cpe     NVARCHAR(500)
);
CREATE INDEX IX_CveProductCpe_CveId ON CveProductCpe (CveId);

-- 受影響的版本資訊
CREATE TABLE CveVersion
(
    Id              INT IDENTITY(1,1) PRIMARY KEY,
    CveId           NVARCHAR(20) NOT NULL,
    Product         NVARCHAR(200),
    Version         NVARCHAR(100),
    Status          NVARCHAR(50),
    LessThan        NVARCHAR(100),
    LessThanOrEqual NVARCHAR(100),
    VersionType     NVARCHAR(50),
    ChangeAt        NVARCHAR(100),
    ChangeStatus    NVARCHAR(50)
);
CREATE INDEX IX_CveVersion_CveId ON CveVersion (CveId);
CREATE INDEX IX_CveVersion_Product ON CveVersion (Product);

-- 受影響的模組資訊
CREATE TABLE CveModule
(
    Id         INT IDENTITY(1,1) PRIMARY KEY,
    CveId      NVARCHAR(20) NOT NULL,
    ModuleName NVARCHAR(200)
);
CREATE INDEX IX_CveModule_CveId ON CveModule (CveId);

-- CVE 描述資訊
CREATE TABLE CveDescription
(
    Id              INT IDENTITY(1,1) PRIMARY KEY,
    CveId           NVARCHAR(20) NOT NULL,
    Language        NVARCHAR(20),
    DescriptionText NVARCHAR(MAX)
);
CREATE INDEX IX_CveDescription_CveId ON CveDescription (CveId);
CREATE INDEX IX_CveDescription_Language ON CveDescription (Language);

-- CVE 支援媒體資訊
CREATE TABLE CveSupportingMedia
(
    Id       INT IDENTITY(1,1) PRIMARY KEY,
    CveId    NVARCHAR(20) NOT NULL,
    Language NVARCHAR(20),
    Type     NVARCHAR(50),
    Base64   BIT,
    Value    NVARCHAR(MAX)
);
CREATE INDEX IX_CveSupportingMedia_CveId ON CveSupportingMedia (CveId);

-- CVSS 評分資訊
CREATE TABLE CveCvssScore
(
    Id                          INT IDENTITY(1,1) PRIMARY KEY,
    CveId                       NVARCHAR(20) NOT NULL,
    Format                      NVARCHAR(50),
    Scenario                    NVARCHAR(100),
    Version                     NVARCHAR(20),
    BaseScore                   FLOAT,
    BaseSeverity                NVARCHAR(20),
    VectorString                NVARCHAR(200),
    AttackVector                NVARCHAR(50),
    AttackComplexity            NVARCHAR(50),
    PrivilegesRequired          NVARCHAR(50),
    UserInteraction             NVARCHAR(50),
    Scope                       NVARCHAR(50),
    ConfidentialityImpact       NVARCHAR(50),
    IntegrityImpact             NVARCHAR(50),
    AvailabilityImpact          NVARCHAR(50),
    Automatable                 NVARCHAR(50),
    Recovery                    NVARCHAR(50),
    Safety                      NVARCHAR(50),
    AttackRequirements          NVARCHAR(100),
    ProviderUrgency             NVARCHAR(50),
    SubConfidentialityImpact    NVARCHAR(50),
    SubIntegrityImpact          NVARCHAR(50),
    SubAvailabilityImpact       NVARCHAR(50),
    ValueDensity                NVARCHAR(50),
    VulnerabilityResponseEffort NVARCHAR(50)
);
CREATE INDEX IX_CveCvssScore_CveId ON CveCvssScore (CveId);
CREATE INDEX IX_CveCvssScore_BaseScore ON CveCvssScore (BaseScore);
CREATE INDEX IX_CveCvssScore_BaseSeverity ON CveCvssScore (BaseSeverity);

-- 問題類型描述
CREATE TABLE CveProblemTypeDescription
(
    Id          INT IDENTITY(1,1) PRIMARY KEY,
    CveId       NVARCHAR(20) NOT NULL,
    CweId       NVARCHAR(20),
    Description NVARCHAR(500),
    Language    NVARCHAR(20),
    Type        NVARCHAR(50)
);
CREATE INDEX IX_CveProblemTypeDescription_CveId ON CveProblemTypeDescription (CveId);
CREATE INDEX IX_CveProblemTypeDescription_CweId ON CveProblemTypeDescription (CweId);

-- 時間線事件
CREATE TABLE CveTimelineEntry
(
    Id        INT IDENTITY(1,1) PRIMARY KEY,
    CveId     NVARCHAR(20) NOT NULL,
    EventTime DATETIME,
    Language  NVARCHAR(20),
    Value     NVARCHAR(MAX)
);
CREATE INDEX IX_CveTimelineEntry_CveId ON CveTimelineEntry (CveId);
CREATE INDEX IX_CveTimelineEntry_EventTime ON CveTimelineEntry (EventTime);

-- 貢獻者資訊
CREATE TABLE CveCredit
(
    Id       INT IDENTITY(1,1) PRIMARY KEY,
    CveId    NVARCHAR(20) NOT NULL,
    Language NVARCHAR(20),
    Type     NVARCHAR(50),
    Value    NVARCHAR(500)
);
CREATE INDEX IX_CveCredit_CveId ON CveCredit (CveId);

-- 參考資料
CREATE TABLE CveReference
(
    Id    INT IDENTITY(1,1) PRIMARY KEY,
    CveId NVARCHAR(20) NOT NULL,
    Url   NVARCHAR(500),
    Name  NVARCHAR(200)
);
CREATE INDEX IX_CveReference_CveId ON CveReference (CveId);

-- 參考資料標籤
CREATE TABLE CveReferenceTag
(
    Id           INT IDENTITY(1,1) PRIMARY KEY,
    CveId        NVARCHAR(20) NOT NULL,
    ReferenceUrl NVARCHAR(500),
    Tag          NVARCHAR(100)
);
CREATE INDEX IX_CveReferenceTag_CveId ON CveReferenceTag (CveId);
CREATE INDEX IX_CveReferenceTag_Tag ON CveReferenceTag (Tag);

-- SSVC 評分資訊
CREATE TABLE CveSsvcOption
(
    Id              INT IDENTITY(1,1) PRIMARY KEY,
    CveId           NVARCHAR(20) NOT NULL,
    SsvcId          NVARCHAR(100),
    Timestamp       DATETIME,
    Role            NVARCHAR(50),
    Version         NVARCHAR(20),
    Exploitation    NVARCHAR(50),
    Automatable     NVARCHAR(50),
    TechnicalImpact NVARCHAR(100)
);
CREATE INDEX IX_CveSsvcOption_CveId ON CveSsvcOption (CveId);

-- 平台資訊（為未來擴展準備）
CREATE TABLE CvePlatform
(
    Id       INT IDENTITY(1,1) PRIMARY KEY,
    CveId    NVARCHAR(20) NOT NULL,
    Platform NVARCHAR(100)
);
CREATE INDEX IX_CvePlatform_CveId ON CvePlatform (CveId);
CREATE INDEX IX_CvePlatform_Platform ON CvePlatform (Platform);

-- 程式檔案資訊（為未來擴展準備）
CREATE TABLE CveProgramFile
(
    Id       INT IDENTITY(1,1) PRIMARY KEY,
    CveId    NVARCHAR(20) NOT NULL,
    FilePath NVARCHAR(500)
);
CREATE INDEX IX_CveProgramFile_CveId ON CveProgramFile (CveId);

-- 程式例程資訊（為未來擴展準備）
CREATE TABLE CveProgramRoutine
(
    Id          INT IDENTITY(1,1) PRIMARY KEY,
    CveId       NVARCHAR(20) NOT NULL,
    RoutineName NVARCHAR(200)
);
CREATE INDEX IX_CveProgramRoutine_CveId ON CveProgramRoutine (CveId);
