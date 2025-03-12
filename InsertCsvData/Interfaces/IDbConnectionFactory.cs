using System.Data;

namespace InsertCsvData.Interfaces;

public interface IDbConnectionFactory
{
    IDbConnection CreateConnection();
    string GetLastInsertIdCommand();
}