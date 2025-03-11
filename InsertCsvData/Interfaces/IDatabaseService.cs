using InsertCsvData.Models;

namespace InsertCsvData.Interfaces;

public interface IDatabaseService
{
    void InsertCveData(Cve.RootCve cveData);
}