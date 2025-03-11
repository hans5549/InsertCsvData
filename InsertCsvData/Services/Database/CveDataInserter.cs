using InsertCsvData.Models;
using Microsoft.Data.SqlClient;

namespace InsertCsvData.Services.Database;

public class CveDataInserter
{
    private readonly string _connectionString;

    public CveDataInserter(string connectionString)
    {
        _connectionString = connectionString;
    }

    public int InsertCveMetadata(Cve.CveMetadata metadata)
    {
        if (metadata == null) return -1;

        using var connection = new SqlConnection(_connectionString);
        connection.Open();

        var sql = @"
            INSERT INTO [CveMetadata] ([CveId], [AssignerOrgId], [AssignerShortName], [State], [DateReserved], [DatePublished], [DateUpdated])
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

    public int InsertRootCve(Cve.RootCve cveData, int cveMetadataId)
    {
        using var connection = new SqlConnection(_connectionString);
        connection.Open();

        var sql = @"
            INSERT INTO [RootCve] ([DataType], [DataVersion], [CveMetadataId])
            VALUES (@DataType, @DataVersion, @CveMetadataId);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@DataType", (object)cveData.DataType ?? DBNull.Value);
        command.Parameters.AddWithValue("@DataVersion", (object)cveData.DataVersion ?? DBNull.Value);
        command.Parameters.AddWithValue("@CveMetadataId", cveMetadataId);

        return Convert.ToInt32(command.ExecuteScalar());
    }

    public int InsertContainers(int rootCveId)
    {
        using var connection = new SqlConnection(_connectionString);
        connection.Open();

        var sql = @"
            INSERT INTO [Containers] ([RootCveId])
            VALUES (@RootCveId);
            SELECT SCOPE_IDENTITY();";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@RootCveId", rootCveId);
        return Convert.ToInt32(command.ExecuteScalar());
    }

    public void UpdateContainersCnaId(int containersId, int cnaId)
    {
        using var connection = new SqlConnection(_connectionString);
        connection.Open();

        var sql = "UPDATE [Containers] SET [CnaId] = @CnaId WHERE [ContainersId] = @ContainersId;";
        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CnaId", cnaId);
        command.Parameters.AddWithValue("@ContainersId", containersId);
        command.ExecuteNonQuery();
    }
}