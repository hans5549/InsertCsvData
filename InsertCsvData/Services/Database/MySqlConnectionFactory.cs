using System.Data;
using InsertCsvData.Interfaces;
using MySql.Data.MySqlClient;

namespace InsertCsvData.Services.Database;

public class MySqlConnectionFactory : IDbConnectionFactory
{
    private readonly string _connectionString;

    public MySqlConnectionFactory(string connectionString)
    {
        _connectionString = connectionString;
    }

    public IDbConnection CreateConnection() => new MySqlConnection(_connectionString);
    public string GetLastInsertIdCommand() => "SELECT LAST_INSERT_ID();";
}