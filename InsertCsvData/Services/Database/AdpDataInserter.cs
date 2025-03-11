using InsertCsvData.Models;
using Microsoft.Data.SqlClient;

namespace InsertCsvData.Services.Database;

public class AdpDataInserter
{
    private readonly string _connectionString;

    public AdpDataInserter(string connectionString)
    {
        _connectionString = connectionString;
    }

    public void InsertAdpContainer(Cve.AdpContainer adp, int containersId)
    {
        using var connection = new SqlConnection(_connectionString);
        connection.Open();

        var providerMetadataId = InsertProviderMetadata(adp.ProviderMetadata, connection);

        var sql = @"
            INSERT INTO [AdpContainer] ([ContainersId], [Title], [ProviderMetadataId])
            VALUES (@ContainersId, @Title, @ProviderMetadataId);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ContainersId", containersId);
        command.Parameters.AddWithValue("@Title", (object)adp.Title ?? DBNull.Value);
        command.Parameters.AddWithValue("@ProviderMetadataId", providerMetadataId);
        int adpId = Convert.ToInt32(command.ExecuteScalar());

        if (adp.Metrics != null)
            foreach (var metric in adp.Metrics)
                InsertAdpMetric(metric, adpId, connection);
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

    private void InsertAdpMetric(Cve.AdpMetric metric, int adpId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [AdpMetric] ([AdpId])
            VALUES (@AdpId);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@AdpId", adpId);
        int adpMetricId = Convert.ToInt32(command.ExecuteScalar());

        if (metric.Other != null) InsertSsvc(metric.Other, adpMetricId, connection);
    }

    private void InsertSsvc(Cve.Ssvc ssvc, int adpMetricId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [Ssvc] ([AdpMetricId], [Type])
            VALUES (@AdpMetricId, @Type);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@AdpMetricId", adpMetricId);
        command.Parameters.AddWithValue("@Type", (object)ssvc.Type ?? DBNull.Value);
        int ssvcId = Convert.ToInt32(command.ExecuteScalar());

        if (ssvc.Content != null) InsertSsvcContent(ssvc.Content, ssvcId, connection);
    }

    private void InsertSsvcContent(Cve.SsvcContent content, int ssvcId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [SsvcContent] ([SsvcId], [Id], [Timestamp], [Role], [Version])
            VALUES (@SsvcId, @Id, @Timestamp, @Role, @Version);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@SsvcId", ssvcId);
        command.Parameters.AddWithValue("@Id", (object)content.Id ?? DBNull.Value);
        command.Parameters.AddWithValue("@Timestamp", content.Timestamp);
        command.Parameters.AddWithValue("@Role", (object)content.Role ?? DBNull.Value);
        command.Parameters.AddWithValue("@Version", (object)content.Version ?? DBNull.Value);
        int ssvcContentId = Convert.ToInt32(command.ExecuteScalar());

        if (content.Options != null)
            foreach (var option in content.Options)
                InsertSsvcOption(option, ssvcContentId, connection);
    }

    private void InsertSsvcOption(Cve.SsvcOption option, int ssvcContentId, SqlConnection connection)
    {
        var sql = @"
            INSERT INTO [SsvcOption] ([SsvcContentId], [Exploitation], [Automatable], [TechnicalImpact])
            VALUES (@SsvcContentId, @Exploitation, @Automatable, @TechnicalImpact);";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@SsvcContentId", ssvcContentId);
        command.Parameters.AddWithValue("@Exploitation", (object)option.Exploitation ?? DBNull.Value);
        command.Parameters.AddWithValue("@Automatable", (object)option.Automatable ?? DBNull.Value);
        command.Parameters.AddWithValue("@TechnicalImpact", (object)option.TechnicalImpact ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}