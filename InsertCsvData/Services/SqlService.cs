using InsertCsvData.Models;
using Microsoft.Data.SqlClient;

namespace InsertCsvData.Services;

public class SqlService
{
    private readonly string _connectionString;

    public SqlService(string connectionString)
    {
        _connectionString = connectionString;
    }

    public void InsertCveData(Cve.RootCve cveData)
    {
        using var connection = new SqlConnection(_connectionString);
        connection.Open();

        // 1. 插入 CveMetadata
        var cveMetadataId = InsertCveMetadata(connection, cveData.CveMetadata);

        // 2. 插入 RootCve
        var rootCveId = InsertRootCve(connection, cveData, cveMetadataId);

        // 3. 插入 Containers 和相關資料
        if (cveData.Containers == null) return;
        var containersId = InsertContainers(connection, rootCveId);

        // 4. 插入 CnaContainer
        if (cveData.Containers.Cna != null)
        {
            var cnaId = InsertCnaContainer(connection, cveData.Containers.Cna);
            UpdateContainersCnaId(connection, containersId, cnaId);

            // 插入 CNA 相關子表
            InsertCnaRelatedData(connection, cveData.Containers.Cna, cnaId);
        }

        // 5. 插入 AdpContainer
        if (cveData.Containers.Adp is not { Count: > 0 }) return;
        foreach (var adp in cveData.Containers.Adp)
            InsertAdpContainer(connection, adp, containersId);
    }

    private int InsertCveMetadata(SqlConnection connection, Cve.CveMetadata metadata)
    {
        if (metadata == null) return -1;

        var sql = @"
                INSERT INTO CveMetadata (CveId, AssignerOrgId, AssignerShortName, State, DateReserved, DatePublished, DateUpdated)
                VALUES (@CveId, @AssignerOrgId, @AssignerShortName, @State, @DateReserved, @DatePublished, @DateUpdated);
                SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CveId", (object)metadata.CveId ?? DBNull.Value);
        command.Parameters.AddWithValue("@AssignerOrgId", (object)metadata.AssignerOrgId ?? DBNull.Value);
        command.Parameters.AddWithValue("@AssignerShortName", (object)metadata.AssignerShortName ?? DBNull.Value);
        command.Parameters.AddWithValue("@State", (object)metadata.State ?? DBNull.Value);
        command.Parameters.AddWithValue("@DateReserved", (object)metadata.DateReserved ?? DBNull.Value);
        command.Parameters.AddWithValue("@DatePublished", (object)metadata.DatePublished ?? DBNull.Value);
        command.Parameters.AddWithValue("@DateUpdated", (object)metadata.DateUpdated ?? DBNull.Value);

        return Convert.ToInt32(command.ExecuteScalar());
    }

    private int InsertRootCve(SqlConnection connection, Cve.RootCve cveData, int cveMetadataId)
    {
        var sql = @"
                INSERT INTO RootCve (DataType, DataVersion, CveMetadataId)
                VALUES (@DataType, @DataVersion, @CveMetadataId);
                SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@DataType", (object)cveData.DataType ?? DBNull.Value);
        command.Parameters.AddWithValue("@DataVersion", (object)cveData.DataVersion ?? DBNull.Value);
        command.Parameters.AddWithValue("@CveMetadataId", cveMetadataId);

        return Convert.ToInt32(command.ExecuteScalar());
    }

    private int InsertContainers(SqlConnection connection, int rootCveId)
    {
        var sql = @"
                INSERT INTO Containers (RootCveId)
                VALUES (@RootCveId);
                SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@RootCveId", rootCveId);
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private int InsertCnaContainer(SqlConnection connection, Cve.CnaContainer cna)
    {
        var providerMetadataId = InsertProviderMetadata(connection, cna.ProviderMetadata);

        var sql = @"
                INSERT INTO CnaContainer (ProviderMetadataId, Title)
                VALUES (@ProviderMetadataId, @Title);
                SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ProviderMetadataId", providerMetadataId);
        command.Parameters.AddWithValue("@Title", (object)cna.Title ?? DBNull.Value);
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private void UpdateContainersCnaId(SqlConnection connection, int containersId, int cnaId)
    {
        var sql = "UPDATE Containers SET CnaId = @CnaId WHERE ContainersId = @ContainersId;";
        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        command.Parameters.AddWithValue("@ContainersId", containersId);
        command.ExecuteNonQuery();
    }

    private int InsertProviderMetadata(SqlConnection connection, Cve.ProviderMetadata metadata)
    {
        if (metadata == null) return -1;

        var sql = @"
                INSERT INTO ProviderMetadata (OrgId, ShortName, DateUpdated)
                VALUES (@OrgId, @ShortName, @DateUpdated);
                SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@OrgId", (object)metadata.OrgId ?? DBNull.Value);
        command.Parameters.AddWithValue("@ShortName", (object)metadata.ShortName ?? DBNull.Value);
        command.Parameters.AddWithValue("@DateUpdated", (object)metadata.DateUpdated ?? DBNull.Value);
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private void InsertCnaRelatedData(SqlConnection connection, Cve.CnaContainer cna, int cnaId)
    {
        // 插入 Affected
        if (cna.Affected != null)
            foreach (var affected in cna.Affected)
            {
                var affectedId = InsertAffected(connection, affected, cnaId);

                // 插入 Versions
                if (affected.Versions != null)
                    foreach (var version in affected.Versions)
                        InsertVersion(connection, version, affectedId);

                // 插入 Modules
                if (affected.Modules != null)
                    foreach (var module in affected.Modules)
                        InsertModule(connection, module, affectedId);
            }

        // 插入 Descriptions
        if (cna.Descriptions != null)
            foreach (var desc in cna.Descriptions)
                InsertDescription(connection, desc, cnaId);

        // 插入 Metrics
        if (cna.Metrics != null)
            foreach (var metric in cna.Metrics)
                InsertMetric(connection, metric, cnaId);

        // 插入 Timeline
        if (cna.Timeline != null)
            foreach (var timeline in cna.Timeline)
                InsertTimelineEntry(connection, timeline, cnaId);

        // 插入 Credits
        if (cna.Credits != null)
            foreach (var credit in cna.Credits)
                InsertCredit(connection, credit, cnaId);

        // 插入 References
        if (cna.References != null)
            foreach (var reference in cna.References)
                InsertReference(connection, reference, cnaId);
    }

    private int InsertAffected(SqlConnection connection, Cve.Affected affected, int cnaId)
    {
        var sql = @"
                INSERT INTO Affected (CnaId, Vendor, Product)
                VALUES (@CnaId, @Vendor, @Product);
                SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        command.Parameters.AddWithValue("@Vendor", (object)affected.Vendor ?? DBNull.Value);
        command.Parameters.AddWithValue("@Product", (object)affected.Product ?? DBNull.Value);
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private void InsertVersion(SqlConnection connection, Cve.Version version, int affectedId)
    {
        var sql = @"
                INSERT INTO Versions (AffectedId, VersionValue, Status, LessThanOrEqual, VersionType)
                VALUES (@AffectedId, @VersionValue, @Status, @LessThanOrEqual, @VersionType);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@AffectedId", affectedId);
        command.Parameters.AddWithValue("@VersionValue", (object)version.VersionValue ?? DBNull.Value);
        command.Parameters.AddWithValue("@Status", (object)version.Status ?? DBNull.Value);
        command.Parameters.AddWithValue("@LessThanOrEqual", (object)version.LessThanOrEqual ?? DBNull.Value);
        command.Parameters.AddWithValue("@VersionType", (object)version.VersionType ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertModule(SqlConnection connection, string moduleName, int affectedId)
    {
        var sql = @"
                INSERT INTO Modules (AffectedId, ModuleName)
                VALUES (@AffectedId, @ModuleName);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@AffectedId", affectedId);
        command.Parameters.AddWithValue("@ModuleName", (object)moduleName ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertDescription(SqlConnection connection, Cve.Description desc, int cnaId)
    {
        var sql = @"
                INSERT INTO Description (CveId, Language, DescriptionText)
                VALUES (@CveId, @Language, @DescriptionText);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CveId", (object)desc.CveId ?? DBNull.Value);
        command.Parameters.AddWithValue("@Language", (object)desc.Language ?? DBNull.Value);
        command.Parameters.AddWithValue("@DescriptionText", (object)desc.DescriptionText ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertMetric(SqlConnection connection, Cve.Metric metric, int cnaId)
    {
        var sql = @"
                INSERT INTO Metric (CnaId)
                VALUES (@CnaId);
                SELECT SCOPE_IDENTITY();";

        int metricId;
        using (var command = new SqlCommand(sql, connection))
        {
            command.Parameters.AddWithValue("@CnaId", cnaId);
            metricId = Convert.ToInt32(command.ExecuteScalar());
        }

        if (metric.CvssV4_0 != null) InsertCvssV4_0(connection, metric.CvssV4_0, metricId);
        if (metric.CvssV3_1 != null) InsertCvssV3_1(connection, metric.CvssV3_1, metricId);
        if (metric.CvssV3_0 != null) InsertCvssV3_0(connection, metric.CvssV3_0, metricId);
        if (metric.CvssV2_0 != null) InsertCvssV2_0(connection, metric.CvssV2_0, metricId);
    }

    private void InsertCvssV4_0(SqlConnection connection, Cve.CvssV4_0 cvss, int metricId)
    {
        var sql = @"
                INSERT INTO CvssV4_0 (MetricId, Version, BaseScore, VectorString, BaseSeverity)
                VALUES (@MetricId, @Version, @BaseScore, @VectorString, @BaseSeverity);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@MetricId", metricId);
        command.Parameters.AddWithValue("@Version", (object)cvss.Version ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseScore", cvss.BaseScore);
        command.Parameters.AddWithValue("@VectorString", (object)cvss.VectorString ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseSeverity", (object)cvss.BaseSeverity ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertCvssV3_1(SqlConnection connection, Cve.CvssV3_1 cvss, int metricId)
    {
        var sql = @"
                INSERT INTO CvssV3_1 (MetricId, Version, BaseScore, VectorString, BaseSeverity)
                VALUES (@MetricId, @Version, @BaseScore, @VectorString, @BaseSeverity);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@MetricId", metricId);
        command.Parameters.AddWithValue("@Version", (object)cvss.Version ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseScore", cvss.BaseScore);
        command.Parameters.AddWithValue("@VectorString", (object)cvss.VectorString ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseSeverity", (object)cvss.BaseSeverity ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertCvssV3_0(SqlConnection connection, Cve.CvssV3_0 cvss, int metricId)
    {
        var sql = @"
                INSERT INTO CvssV3_0 (MetricId, Version, BaseScore, VectorString, BaseSeverity)
                VALUES (@MetricId, @Version, @BaseScore, @VectorString, @BaseSeverity);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@MetricId", metricId);
        command.Parameters.AddWithValue("@Version", (object)cvss.Version ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseScore", cvss.BaseScore);
        command.Parameters.AddWithValue("@VectorString", (object)cvss.VectorString ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseSeverity", (object)cvss.BaseSeverity ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertCvssV2_0(SqlConnection connection, Cve.CvssV2_0 cvss, int metricId)
    {
        var sql = @"
                INSERT INTO CvssV2_0 (MetricId, Version, BaseScore, VectorString)
                VALUES (@MetricId, @Version, @BaseScore, @VectorString);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@MetricId", metricId);
        command.Parameters.AddWithValue("@Version", (object)cvss.Version ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseScore", cvss.BaseScore);
        command.Parameters.AddWithValue("@VectorString", (object)cvss.VectorString ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertTimelineEntry(SqlConnection connection, Cve.TimelineEntry timeline, int cnaId)
    {
        var sql = @"
                INSERT INTO TimelineEntry (CnaId, CveId, Time, Language, Value)
                VALUES (@CnaId, @CveId, @Time, @Language, @Value);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        command.Parameters.AddWithValue("@CveId", (object)timeline.CveId ?? DBNull.Value);
        command.Parameters.AddWithValue("@Time", timeline.Time);
        command.Parameters.AddWithValue("@Language", (object)timeline.Language ?? DBNull.Value);
        command.Parameters.AddWithValue("@Value", (object)timeline.Value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertCredit(SqlConnection connection, Cve.Credit credit, int cnaId)
    {
        var sql = @"
                INSERT INTO Credit (CnaId, CveId, Language, Type, Value)
                VALUES (@CnaId, @CveId, @Language, @Type, @Value);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        command.Parameters.AddWithValue("@CveId", (object)credit.CveId ?? DBNull.Value);
        command.Parameters.AddWithValue("@Language", (object)credit.Language ?? DBNull.Value);
        command.Parameters.AddWithValue("@Type", (object)credit.Type ?? DBNull.Value);
        command.Parameters.AddWithValue("@Value", (object)credit.Value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertReference(SqlConnection connection, Cve.Reference reference, int cnaId)
    {
        var sql = @"
                INSERT INTO Reference (CnaId, CveId, Url, Name)
                VALUES (@CnaId, @CveId, @Url, @Name);
                SELECT SCOPE_IDENTITY();";

        int referenceId;
        using (var command = new SqlCommand(sql, connection))
        {
            command.Parameters.AddWithValue("@CnaId", cnaId);
            command.Parameters.AddWithValue("@CveId", (object)reference.CveId ?? DBNull.Value);
            command.Parameters.AddWithValue("@Url", (object)reference.Url ?? DBNull.Value);
            command.Parameters.AddWithValue("@Name", (object)reference.Name ?? DBNull.Value);
            referenceId = Convert.ToInt32(command.ExecuteScalar());
        }

        if (reference.Tags != null)
            foreach (var tag in reference.Tags)
                InsertReferenceTag(connection, tag, referenceId);
    }

    private void InsertReferenceTag(SqlConnection connection, string tag, int referenceId)
    {
        var sql = @"
                INSERT INTO ReferenceTags (ReferenceId, Tag)
                VALUES (@ReferenceId, @Tag);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ReferenceId", referenceId);
        command.Parameters.AddWithValue("@Tag", (object)tag ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertAdpContainer(SqlConnection connection, Cve.AdpContainer adp, int containersId)
    {
        var providerMetadataId = InsertProviderMetadata(connection, adp.ProviderMetadata);

        var sql = @"
                INSERT INTO AdpContainer (ContainersId, Title, ProviderMetadataId)
                VALUES (@ContainersId, @Title, @ProviderMetadataId);
                SELECT SCOPE_IDENTITY();";

        int adpId;
        using (var command = new SqlCommand(sql, connection))
        {
            command.Parameters.AddWithValue("@ContainersId", containersId);
            command.Parameters.AddWithValue("@Title", (object)adp.Title ?? DBNull.Value);
            command.Parameters.AddWithValue("@ProviderMetadataId", providerMetadataId);
            adpId = Convert.ToInt32(command.ExecuteScalar());
        }

        if (adp.Metrics != null)
            foreach (var metric in adp.Metrics)
                InsertAdpMetric(connection, metric, adpId);
    }

    private void InsertAdpMetric(SqlConnection connection, Cve.AdpMetric metric, int adpId)
    {
        var sql = @"
                INSERT INTO AdpMetric (AdpId)
                VALUES (@AdpId);
                SELECT SCOPE_IDENTITY();";

        int adpMetricId;
        using (var command = new SqlCommand(sql, connection))
        {
            command.Parameters.AddWithValue("@AdpId", adpId);
            adpMetricId = Convert.ToInt32(command.ExecuteScalar());
        }

        if (metric.Other != null) InsertSsvc(connection, metric.Other, adpMetricId);
    }

    private void InsertSsvc(SqlConnection connection, Cve.Ssvc ssvc, int adpMetricId)
    {
        var sql = @"
                INSERT INTO Ssvc (AdpMetricId, Type)
                VALUES (@AdpMetricId, @Type);
                SELECT SCOPE_IDENTITY();";

        int ssvcId;
        using (var command = new SqlCommand(sql, connection))
        {
            command.Parameters.AddWithValue("@AdpMetricId", adpMetricId);
            command.Parameters.AddWithValue("@Type", (object)ssvc.Type ?? DBNull.Value);
            ssvcId = Convert.ToInt32(command.ExecuteScalar());
        }

        if (ssvc.Content != null) InsertSsvcContent(connection, ssvc.Content, ssvcId);
    }

    private void InsertSsvcContent(SqlConnection connection, Cve.SsvcContent content, int ssvcId)
    {
        var sql = @"
                INSERT INTO SsvcContent (SsvcId, Id, Timestamp, Role, Version)
                VALUES (@SsvcId, @Id, @Timestamp, @Role, @Version);
                SELECT SCOPE_IDENTITY();";

        int ssvcContentId;
        using (var command = new SqlCommand(sql, connection))
        {
            command.Parameters.AddWithValue("@SsvcId", ssvcId);
            command.Parameters.AddWithValue("@Id", (object)content.Id ?? DBNull.Value);
            command.Parameters.AddWithValue("@Timestamp", content.Timestamp);
            command.Parameters.AddWithValue("@Role", (object)content.Role ?? DBNull.Value);
            command.Parameters.AddWithValue("@Version", (object)content.Version ?? DBNull.Value);
            ssvcContentId = Convert.ToInt32(command.ExecuteScalar());
        }

        if (content.Options != null)
            foreach (var option in content.Options)
                InsertSsvcOption(connection, option, ssvcContentId);
    }

    private void InsertSsvcOption(SqlConnection connection, Cve.SsvcOption option, int ssvcContentId)
    {
        var sql = @"
                INSERT INTO SsvcOption (SsvcContentId, Exploitation, Automatable, TechnicalImpact)
                VALUES (@SsvcContentId, @Exploitation, @Automatable, @TechnicalImpact);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@SsvcContentId", ssvcContentId);
        command.Parameters.AddWithValue("@Exploitation", (object)option.Exploitation ?? DBNull.Value);
        command.Parameters.AddWithValue("@Automatable", (object)option.Automatable ?? DBNull.Value);
        command.Parameters.AddWithValue("@TechnicalImpact", (object)option.TechnicalImpact ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}