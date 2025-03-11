using InsertCsvData.Models;
using Microsoft.Data.SqlClient;

namespace InsertCsvData.Services.Database;

public class CnaDataInserter
{
    private readonly string _connectionString;

    public CnaDataInserter(string connectionString)
    {
        _connectionString = connectionString;
    }

    public int InsertCnaContainer(Cve.CnaContainer cna)
    {
        using var connection = new SqlConnection(_connectionString);
        connection.Open();

        var providerMetadataId = InsertProviderMetadata(cna.ProviderMetadata, connection);

        var sql = @"
            INSERT INTO [CnaContainer] ([ProviderMetadataId], [Title])
            VALUES (@ProviderMetadataId, @Title);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ProviderMetadataId", providerMetadataId);
        command.Parameters.AddWithValue("@Title", (object)cna.Title ?? DBNull.Value);
        return Convert.ToInt32(command.ExecuteScalar());
    }

    public void InsertCnaRelatedData(Cve.CnaContainer cna, int cnaId)
    {
        using var connection = new SqlConnection(_connectionString);
        connection.Open();

        if (cna.Affected != null)
            foreach (var affected in cna.Affected)
                InsertAffected(affected, cnaId, connection);

        if (cna.Descriptions != null)
            foreach (var desc in cna.Descriptions)
                InsertDescription(desc, cnaId, connection);

        if (cna.Metrics != null)
            foreach (var metric in cna.Metrics)
                InsertMetric(metric, cnaId, connection);

        if (cna.Timeline != null)
            foreach (var timeline in cna.Timeline)
                InsertTimelineEntry(timeline, cnaId, connection);

        if (cna.Credits != null)
            foreach (var credit in cna.Credits)
                InsertCredit(credit, cnaId, connection);

        if (cna.References != null)
            foreach (var reference in cna.References)
                InsertReference(reference, cnaId, connection);
    }

    private int InsertProviderMetadata(Cve.ProviderMetadata metadata, SqlConnection connection)
    {
        if (metadata == null) return -1;

        var sql = @"
            INSERT INTO [ProviderMetadata] ([OrgId], [ShortName], [DateUpdated])
            VALUES (@OrgId, @ShortName, @DateUpdated);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@OrgId", (object)metadata.OrgId ?? DBNull.Value);
        command.Parameters.AddWithValue("@ShortName", (object)metadata.ShortName ?? DBNull.Value);
        command.Parameters.AddWithValue("@DateUpdated", (object)metadata.DateUpdated ?? DBNull.Value);
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private void InsertAffected(Cve.Affected affected, int cnaId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [Affected] ([CnaId], [Vendor], [Product])
            VALUES (@CnaId, @Vendor, @Product);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        command.Parameters.AddWithValue("@Vendor", (object)affected.Vendor ?? DBNull.Value);
        command.Parameters.AddWithValue("@Product", (object)affected.Product ?? DBNull.Value);
        int affectedId = Convert.ToInt32(command.ExecuteScalar());

        if (affected.Versions != null)
            foreach (var version in affected.Versions)
                InsertVersion(version, affectedId, connection);

        if (affected.Modules != null)
            foreach (var module in affected.Modules)
                InsertModule(module, affectedId, connection);
    }

    private void InsertVersion(Cve.Version version, int affectedId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [Versions] ([AffectedId], [VersionValue], [Status], [LessThanOrEqual], [VersionType])
            VALUES (@AffectedId, @VersionValue, @Status, @LessThanOrEqual, @VersionType);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@AffectedId", affectedId);
        command.Parameters.AddWithValue("@VersionValue", (object)version.VersionValue ?? DBNull.Value);
        command.Parameters.AddWithValue("@Status", (object)version.Status ?? DBNull.Value);
        command.Parameters.AddWithValue("@LessThanOrEqual", (object)version.LessThanOrEqual ?? DBNull.Value);
        command.Parameters.AddWithValue("@VersionType", (object)version.VersionType ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertModule(string moduleName, int affectedId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [Modules] ([AffectedId], [ModuleName])
            VALUES (@AffectedId, @ModuleName);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@AffectedId", affectedId);
        command.Parameters.AddWithValue("@ModuleName", (object)moduleName ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertDescription(Cve.Description desc, int cnaId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [Description] ([CveId], [Language], [DescriptionText])
            VALUES (@CveId, @Language, @DescriptionText);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CveId", (object)desc.CveId ?? DBNull.Value);
        command.Parameters.AddWithValue("@Language", (object)desc.Language ?? DBNull.Value);
        command.Parameters.AddWithValue("@DescriptionText", (object)desc.DescriptionText ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertMetric(Cve.Metric metric, int cnaId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [Metric] ([CnaId])
            VALUES (@CnaId);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        int metricId = Convert.ToInt32(command.ExecuteScalar());

        if (metric.CvssV4_0 != null) InsertCvssV4_0(metric.CvssV4_0, metricId, connection);
        if (metric.CvssV3_1 != null) InsertCvssV3_1(metric.CvssV3_1, metricId, connection);
        if (metric.CvssV3_0 != null) InsertCvssV3_0(metric.CvssV3_0, metricId, connection);
        if (metric.CvssV2_0 != null) InsertCvssV2_0(metric.CvssV2_0, metricId, connection);
    }

    private void InsertCvssV4_0(Cve.CvssV4_0 cvss, int metricId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [CvssV4_0] ([MetricId], [Version], [BaseScore], [VectorString], [BaseSeverity])
            VALUES (@MetricId, @Version, @BaseScore, @VectorString, @BaseSeverity);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@MetricId", metricId);
        command.Parameters.AddWithValue("@Version", (object)cvss.Version ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseScore", cvss.BaseScore);
        command.Parameters.AddWithValue("@VectorString", (object)cvss.VectorString ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseSeverity", (object)cvss.BaseSeverity ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertCvssV3_1(Cve.CvssV3_1 cvss, int metricId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [CvssV3_1] ([MetricId], [Version], [BaseScore], [VectorString], [BaseSeverity])
            VALUES (@MetricId, @Version, @BaseScore, @VectorString, @BaseSeverity);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@MetricId", metricId);
        command.Parameters.AddWithValue("@Version", (object)cvss.Version ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseScore", cvss.BaseScore);
        command.Parameters.AddWithValue("@VectorString", (object)cvss.VectorString ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseSeverity", (object)cvss.BaseSeverity ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertCvssV3_0(Cve.CvssV3_0 cvss, int metricId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [CvssV3_0] ([MetricId], [Version], [BaseScore], [VectorString], [BaseSeverity])
            VALUES (@MetricId, @Version, @BaseScore, @VectorString, @BaseSeverity);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@MetricId", metricId);
        command.Parameters.AddWithValue("@Version", (object)cvss.Version ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseScore", cvss.BaseScore);
        command.Parameters.AddWithValue("@VectorString", (object)cvss.VectorString ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseSeverity", (object)cvss.BaseSeverity ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertCvssV2_0(Cve.CvssV2_0 cvss, int metricId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [CvssV2_0] ([MetricId], [Version], [BaseScore], [VectorString])
            VALUES (@MetricId, @Version, @BaseScore, @VectorString);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@MetricId", metricId);
        command.Parameters.AddWithValue("@Version", (object)cvss.Version ?? DBNull.Value);
        command.Parameters.AddWithValue("@BaseScore", cvss.BaseScore);
        command.Parameters.AddWithValue("@VectorString", (object)cvss.VectorString ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertTimelineEntry(Cve.TimelineEntry timeline, int cnaId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [TimelineEntry] ([CnaId], [CveId], [Time], [Language], [Value])
            VALUES (@CnaId, @CveId, @Time, @Language, @Value);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        command.Parameters.AddWithValue("@CveId", (object)timeline.CveId ?? DBNull.Value);
        command.Parameters.AddWithValue("@Time", timeline.Time);
        command.Parameters.AddWithValue("@Language", (object)timeline.Language ?? DBNull.Value);
        command.Parameters.AddWithValue("@Value", (object)timeline.Value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertCredit(Cve.Credit credit, int cnaId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [Credit] ([CnaId], [CveId], [Language], [Type], [Value])
            VALUES (@CnaId, @CveId, @Language, @Type, @Value);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        command.Parameters.AddWithValue("@CveId", (object)credit.CveId ?? DBNull.Value);
        command.Parameters.AddWithValue("@Language", (object)credit.Language ?? DBNull.Value);
        command.Parameters.AddWithValue("@Type", (object)credit.Type ?? DBNull.Value);
        command.Parameters.AddWithValue("@Value", (object)credit.Value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void InsertReference(Cve.Reference reference, int cnaId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [Reference] ([CnaId], [CveId], [Url], [Name])
            VALUES (@CnaId, @CveId, @Url, @Name);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        command.Parameters.AddWithValue("@CveId", (object)reference.CveId ?? DBNull.Value);
        command.Parameters.AddWithValue("@Url", (object)reference.Url ?? DBNull.Value);
        command.Parameters.AddWithValue("@Name", (object)reference.Name ?? DBNull.Value);
        int referenceId = Convert.ToInt32(command.ExecuteScalar());

        if (reference.Tags != null)
            foreach (var tag in reference.Tags)
                InsertReferenceTag(tag, referenceId, connection);
    }

    private void InsertReferenceTag(string tag, int referenceId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [ReferenceTags] ([ReferenceId], [Tag])
            VALUES (@ReferenceId, @Tag);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ReferenceId", referenceId);
        command.Parameters.AddWithValue("@Tag", (object)tag ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}