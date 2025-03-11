using InsertCsvData.Interfaces;
using InsertCsvData.Models;

namespace InsertCsvData.Services.Database;

public class SqlDatabaseService : IDatabaseService
{
    private readonly string _connectionString;
    private readonly CveDataInserter _cveDataInserter;
    private readonly CnaDataInserter _cnaDataInserter;
    private readonly AdpDataInserter _adpDataInserter;

    public SqlDatabaseService(string connectionString)
    {
        _connectionString = connectionString;
        _cveDataInserter = new CveDataInserter(_connectionString);
        _cnaDataInserter = new CnaDataInserter(_connectionString);
        _adpDataInserter = new AdpDataInserter(_connectionString);
    }

    public void InsertCveData(Cve.RootCve cveData)
    {
        int cveMetadataId = _cveDataInserter.InsertCveMetadata(cveData.CveMetadata);
        int rootCveId = _cveDataInserter.InsertRootCve(cveData, cveMetadataId);

        if (cveData.Containers == null) return;
        int containersId = _cveDataInserter.InsertContainers(rootCveId);

        if (cveData.Containers.Cna != null)
        {
            int cnaId = _cnaDataInserter.InsertCnaContainer(cveData.Containers.Cna);
            _cveDataInserter.UpdateContainersCnaId(containersId, cnaId);
            _cnaDataInserter.InsertCnaRelatedData(cveData.Containers.Cna, cnaId);
        }

        if (cveData.Containers.Adp is { Count: > 0 })
        {
            foreach (var adp in cveData.Containers.Adp)
                _adpDataInserter.InsertAdpContainer(adp, containersId);
        }
    }
}