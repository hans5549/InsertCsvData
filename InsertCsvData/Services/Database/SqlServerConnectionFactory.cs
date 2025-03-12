using System.Data;
using InsertCsvData.Interfaces;
using Microsoft.Data.SqlClient;

namespace InsertCsvData.Services.Database;

public class SqlServerConnectionFactory : IDbConnectionFactory
{
    private readonly string _connectionString;

    public SqlServerConnectionFactory(string connectionString)
    {
        _connectionString = connectionString;
    }

    public IDbConnection CreateConnection() => new SqlConnection(_connectionString);
    public string GetLastInsertIdCommand() => "SELECT SCOPE_IDENTITY();";
}