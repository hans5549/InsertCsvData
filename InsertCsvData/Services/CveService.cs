using InsertCsvData.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace InsertCsvData.Services;

public class CveService
{
    public static Cve.RootCve ParseCveData(string jsonData)
    {
        return JsonConvert.DeserializeObject<Cve.RootCve>(jsonData);
    }

    // 處理結果類型（簡化版）
    public class MappingResult
    {
        public bool IsSuccess { get; set; }
        public string OriginalFilePath { get; set; }
    }

    // 單個檔案的映射方法（簡化版）
    private static MappingResult MapCveToModels(string filePath, string failureDirectory)
    {
        try
        {
            if (!Directory.Exists(failureDirectory)) Directory.CreateDirectory(failureDirectory);

            // 使用流式讀取 JSON
            using var streamReader = new StreamReader(filePath);
            using var jsonReader = new JsonTextReader(streamReader);
            var serializer = new JsonSerializer();
            var rootCve = serializer.Deserialize<Cve.RootCve>(jsonReader);

            if (rootCve == null || rootCve.CveMetadata == null)
                throw new Exception("Failed to parse JSON data or missing critical CVE metadata.");

            var cveRecords = new List<Cve.CveRecord>
            {
                new()
                {
                    CveId = rootCve.CveMetadata.CveId ?? throw new Exception("CVE ID is missing."),
                    Title = rootCve.Containers.Cna?.Title ?? "Unknown Title",
                    DatePublished = rootCve.CveMetadata.DatePublished,
                    DateReserved = rootCve.CveMetadata.DateReserved,
                    DateUpdated = rootCve.CveMetadata.DateUpdated,
                    AssignerOrgId = rootCve.CveMetadata.AssignerOrgId,
                    AssignerShortName = rootCve.CveMetadata.AssignerShortName,
                    State = rootCve.CveMetadata.State
                }
            };

            return new MappingResult
            {
                IsSuccess = true,
                OriginalFilePath = filePath
            };
        }
        catch (Exception)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var fileName = Path.GetFileName(filePath);
                    var destPath = Path.Combine(failureDirectory, fileName);
                    File.Move(filePath, destPath);
                }
            }
            catch
            {
                // 移動失敗時靜默處理
            }

            return new MappingResult
            {
                IsSuccess = false,
                OriginalFilePath = filePath
            };
        }
    }

    /// <summary>
    /// 遍歷指定路徑下的所有子資料夾，處理 JSON 檔案，並即時顯示進度
    /// </summary>
    /// <param name="rootDirectory">根目錄路徑</param>
    /// <param name="failureDirectory">失敗檔案的目標目錄</param>
    public static void ProcessJsonFilesInDirectory(string rootDirectory, string failureDirectory)
    {
        try
        {
            if (!Directory.Exists(rootDirectory))
            {
                Console.WriteLine($"Error: Root directory not found: {rootDirectory}");
                return;
            }

            // 獲取所有 JSON 檔案
            var jsonFiles = Directory.EnumerateFiles(rootDirectory, "*.json", SearchOption.AllDirectories).ToList();
            var totalFiles = jsonFiles.Count;
            var successCount = 0;
            var failureCount = 0;
            var processedCount = 0;

            // 初始化進度顯示
            UpdateProgress(totalFiles, successCount, failureCount);

            foreach (var filePath in jsonFiles)
            {
                var result = MapCveToModels(filePath, failureDirectory);

                processedCount++;
                if (result.IsSuccess)
                    successCount++;
                else
                    failureCount++;

                // 即時更新進度
                UpdateProgress(totalFiles, successCount, failureCount);
            }

            // 最終結果
            Console.WriteLine(); // 換行
            Console.WriteLine(
                $"Processing completed. Total: {totalFiles}, Success: {successCount}, Failed: {failureCount}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing directory {rootDirectory}: {ex.Message}");
        }
    }

    // 更新並顯示進度
    private static void UpdateProgress(int total, int success, int failed)
    {
        Console.CursorLeft = 0; // 將光標移到行首
        Console.Write($"Progress: Processed {success + failed}/{total} | Success: {success} | Failed: {failed}");
    }

    /// <summary>
    /// 將 CveRecord 及其相關資料完整列印到控制台
    /// </summary>
    /// <param name="rootCve">包含完整 CVE 資料的 RootCve 物件</param>
    public static void PrintFullCveDetails(Cve.RootCve rootCve)
    {
        if (rootCve == null || rootCve.CveMetadata == null)
        {
            Console.WriteLine("Error: RootCve or CveMetadata is null.");
            return;
        }

        // 列印基本資訊 (CveMetadata)
        Console.WriteLine("=== CVE Metadata ===");
        Console.WriteLine($"CVE ID: {rootCve.CveMetadata.CveId ?? "N/A"}");
        Console.WriteLine($"Assigner Org ID: {rootCve.CveMetadata.AssignerOrgId ?? "N/A"}");
        Console.WriteLine($"Assigner Short Name: {rootCve.CveMetadata.AssignerShortName ?? "N/A"}");
        Console.WriteLine($"State: {rootCve.CveMetadata.State ?? "N/A"}");
        Console.WriteLine(
            $"Date Reserved: {(rootCve.CveMetadata.DateReserved.HasValue ? rootCve.CveMetadata.DateReserved.Value.ToString("yyyy-MM-dd HH:mm:ss") : "N/A")}");
        Console.WriteLine(
            $"Date Published: {(rootCve.CveMetadata.DatePublished.HasValue ? rootCve.CveMetadata.DatePublished.Value.ToString("yyyy-MM-dd HH:mm:ss") : "N/A")}");
        Console.WriteLine(
            $"Date Updated: {(rootCve.CveMetadata.DateUpdated.HasValue ? rootCve.CveMetadata.DateUpdated.Value.ToString("yyyy-MM-dd HH:mm:ss") : "N/A")}");
        Console.WriteLine();

        // 列印 CNA 容器資料
        if (rootCve.Containers?.Cna != null)
        {
            var cna = rootCve.Containers.Cna;
            Console.WriteLine("=== CNA Container ===");
            Console.WriteLine($"Title: {cna.Title ?? "N/A"}");

            // 提供者元資料
            if (cna.ProviderMetadata != null)
            {
                Console.WriteLine("--- Provider Metadata ---");
                Console.WriteLine($"Org ID: {cna.ProviderMetadata.OrgId ?? "N/A"}");
                Console.WriteLine($"Short Name: {cna.ProviderMetadata.ShortName ?? "N/A"}");
                Console.WriteLine(
                    $"Date Updated: {(cna.ProviderMetadata.DateUpdated.HasValue ? cna.ProviderMetadata.DateUpdated.Value.ToString("yyyy-MM-dd HH:mm:ss") : "N/A")}");
            }

            // 問題類型
            if (cna.ProblemTypes?.Count > 0)
            {
                Console.WriteLine("--- Problem Types ---");
                foreach (var problem in cna.ProblemTypes)
                    if (problem.Descriptions?.Count > 0)
                        foreach (var desc in problem.Descriptions)
                            Console.WriteLine(
                                $"CWE ID: {desc.CweId ?? "N/A"}, Description: {desc.Description ?? "N/A"}, Language: {desc.Language ?? "N/A"}");
            }

            // 受影響的產品
            if (cna.Affected?.Count > 0)
            {
                Console.WriteLine("--- Affected Products ---");
                foreach (var affected in cna.Affected)
                {
                    Console.WriteLine($"Vendor: {affected.Vendor ?? "N/A"}, Product: {affected.Product ?? "N/A"}");
                    if (affected.Versions?.Count > 0)
                    {
                        Console.WriteLine("  Versions:");
                        foreach (var version in affected.Versions)
                            Console.WriteLine(
                                $"    Version: {version.VersionValue ?? "N/A"}, Status: {version.Status ?? "N/A"}, LessThanOrEqual: {version.LessThanOrEqual ?? "N/A"}, Type: {version.VersionType ?? "N/A"}");
                    }

                    if (affected.Modules?.Count > 0)
                        Console.WriteLine($"  Modules: {string.Join(", ", affected.Modules)}");
                }
            }

            // 描述
            if (cna.Descriptions?.Count > 0)
            {
                Console.WriteLine("--- Descriptions ---");
                foreach (var desc in cna.Descriptions)
                    Console.WriteLine(
                        $"Language: {desc.Language ?? "N/A"}, Description: {desc.DescriptionText ?? "N/A"}");
            }

            // 評分指標
            if (cna.Metrics?.Count > 0)
            {
                Console.WriteLine("--- Metrics ---");
                foreach (var metric in cna.Metrics)
                {
                    if (metric.CvssV4_0 != null)
                        Console.WriteLine(
                            $"CVSS v4.0 - Score: {metric.CvssV4_0.BaseScore}, Severity: {metric.CvssV4_0.BaseSeverity ?? "N/A"}, Vector: {metric.CvssV4_0.VectorString ?? "N/A"}");
                    if (metric.CvssV3_1 != null)
                        Console.WriteLine(
                            $"CVSS v3.1 - Score: {metric.CvssV3_1.BaseScore}, Severity: {metric.CvssV3_1.BaseSeverity ?? "N/A"}, Vector: {metric.CvssV3_1.VectorString ?? "N/A"}");
                    if (metric.CvssV3_0 != null)
                        Console.WriteLine(
                            $"CVSS v3.0 - Score: {metric.CvssV3_0.BaseScore}, Severity: {metric.CvssV3_0.BaseSeverity ?? "N/A"}, Vector: {metric.CvssV3_0.VectorString ?? "N/A"}");
                    if (metric.CvssV2_0 != null)
                        Console.WriteLine(
                            $"CVSS v2.0 - Score: {metric.CvssV2_0.BaseScore}, Vector: {metric.CvssV2_0.VectorString ?? "N/A"}");
                }
            }

            // 時間線
            if (cna.Timeline?.Count > 0)
            {
                Console.WriteLine("--- Timeline ---");
                foreach (var entry in cna.Timeline)
                    Console.WriteLine(
                        $"Time: {entry.Time.ToString("yyyy-MM-dd HH:mm:ss")}, Description: {entry.Value ?? "N/A"}, Language: {entry.Language ?? "N/A"}");
            }

            // 貢獻者
            if (cna.Credits?.Count > 0)
            {
                Console.WriteLine("--- Credits ---");
                foreach (var credit in cna.Credits)
                    Console.WriteLine(
                        $"Type: {credit.Type ?? "N/A"}, Value: {credit.Value ?? "N/A"}, Language: {credit.Language ?? "N/A"}");
            }

            // 參考資料
            if (cna.References?.Count > 0)
            {
                Console.WriteLine("--- References ---");
                foreach (var reference in cna.References)
                    Console.WriteLine(
                        $"URL: {reference.Url ?? "N/A"}, Name: {reference.Name ?? "N/A"}, Tags: {(reference.Tags != null ? string.Join(", ", reference.Tags) : "N/A")}");
            }

            Console.WriteLine();
        }

        // 列印 ADP 容器資料
        if (rootCve.Containers?.Adp?.Count > 0)
        {
            Console.WriteLine("=== ADP Containers ===");
            foreach (var adp in rootCve.Containers.Adp)
            {
                Console.WriteLine($"Title: {adp.Title ?? "N/A"}");
                if (adp.ProviderMetadata != null)
                {
                    Console.WriteLine("--- Provider Metadata ---");
                    Console.WriteLine($"Org ID: {adp.ProviderMetadata.OrgId ?? "N/A"}");
                    Console.WriteLine($"Short Name: {adp.ProviderMetadata.ShortName ?? "N/A"}");
                    Console.WriteLine(
                        $"Date Updated: {(adp.ProviderMetadata.DateUpdated.HasValue ? adp.ProviderMetadata.DateUpdated.Value.ToString("yyyy-MM-dd HH:mm:ss") : "N/A")}");
                }

                if (adp.Metrics?.Count > 0)
                {
                    Console.WriteLine("--- ADP Metrics ---");
                    foreach (var metric in adp.Metrics)
                        if (metric.Other != null && metric.Other.Content != null)
                        {
                            Console.WriteLine(
                                $"SSVC - ID: {metric.Other.Content.Id ?? "N/A"}, Timestamp: {metric.Other.Content.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")}, Version: {metric.Other.Content.Version ?? "N/A"}");
                            if (metric.Other.Content.Options?.Count > 0)
                                foreach (var option in metric.Other.Content.Options)
                                    Console.WriteLine(
                                        $"  Exploitation: {option.Exploitation ?? "N/A"}, Automatable: {option.Automatable ?? "N/A"}, Technical Impact: {option.TechnicalImpact ?? "N/A"}");
                        }
                }
            }

            Console.WriteLine();
        }

        Console.WriteLine("==========================");
    }

    public static bool VerifyCveModelAgainstJson(string filePath, Cve.RootCve rootCve)
    {
        try
        {
            var jsonContent = File.ReadAllText(filePath);
            var originalJson = JObject.Parse(jsonContent);

            var isMatch = true;
            var discrepancies = new List<string>();

            if (originalJson["dataType"]?.ToString() != rootCve.DataType)
            {
                isMatch = false;
                discrepancies.Add(
                    $"DataType mismatch: JSON = '{originalJson["dataType"]}', Model = '{rootCve.DataType}'");
            }

            if (originalJson["dataVersion"]?.ToString() != rootCve.DataVersion)
            {
                isMatch = false;
                discrepancies.Add(
                    $"DataVersion mismatch: JSON = '{originalJson["dataVersion"]}', Model = '{rootCve.DataVersion}'");
            }

            if (rootCve.CveMetadata != null)
            {
                var jsonMetadata = originalJson["cveMetadata"] as JObject;
                isMatch &= VerifyCveMetadata(jsonMetadata, rootCve.CveMetadata, discrepancies);
            }

            if (rootCve.Containers != null)
            {
                var jsonContainers = originalJson["containers"] as JObject;
                isMatch &= VerifyContainers(jsonContainers, rootCve.Containers, discrepancies);
            }

            if (isMatch)
            {
                Console.WriteLine($"Verification passed for file: {filePath}");
            }
            else
            {
                Console.WriteLine($"Verification failed for file: {filePath}");
                Console.WriteLine("Discrepancies found:");
                foreach (var discrepancy in discrepancies) Console.WriteLine($"- {discrepancy}");
            }

            return isMatch;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error verifying file {filePath}: {ex.Message}");
            return false;
        }
    }

    private static bool VerifyCveMetadata(JObject jsonMetadata, Cve.CveMetadata metadata, List<string> discrepancies)
    {
        var isMatch = true;
        if (jsonMetadata == null)
        {
            discrepancies.Add("CveMetadata is missing in JSON but present in model");
            return false;
        }

        if (jsonMetadata["cveId"]?.ToString() != metadata.CveId)
        {
            isMatch = false;
            discrepancies.Add(
                $"CveMetadata.CveId mismatch: JSON = '{jsonMetadata["cveId"]}', Model = '{metadata.CveId}'");
        }

        if (jsonMetadata["assignerOrgId"]?.ToString() != metadata.AssignerOrgId)
        {
            isMatch = false;
            discrepancies.Add(
                $"CveMetadata.AssignerOrgId mismatch: JSON = '{jsonMetadata["assignerOrgId"]}', Model = '{metadata.AssignerOrgId}'");
        }

        if (jsonMetadata["assignerShortName"]?.ToString() != metadata.AssignerShortName)
        {
            isMatch = false;
            discrepancies.Add(
                $"CveMetadata.AssignerShortName mismatch: JSON = '{jsonMetadata["assignerShortName"]}', Model = '{metadata.AssignerShortName}'");
        }

        if (jsonMetadata["state"]?.ToString() != metadata.State)
        {
            isMatch = false;
            discrepancies.Add(
                $"CveMetadata.State mismatch: JSON = '{jsonMetadata["state"]}', Model = '{metadata.State}'");
        }

        // 時間比較：解析 JSON 時間並與模型中的 DateTime 比較
        if (!CompareDateTime(jsonMetadata["dateReserved"]?.ToString(), metadata.DateReserved))
        {
            isMatch = false;
            discrepancies.Add(
                $"CveMetadata.DateReserved mismatch: JSON = '{jsonMetadata["dateReserved"]}', Model = '{metadata.DateReserved?.ToString("yyyy-MM-dd HH:mm:ss")}'");
        }

        if (!CompareDateTime(jsonMetadata["datePublished"]?.ToString(), metadata.DatePublished))
        {
            isMatch = false;
            discrepancies.Add(
                $"CveMetadata.DatePublished mismatch: JSON = '{jsonMetadata["datePublished"]}', Model = '{metadata.DatePublished?.ToString("yyyy-MM-dd HH:mm:ss")}'");
        }

        if (!CompareDateTime(jsonMetadata["dateUpdated"]?.ToString(), metadata.DateUpdated))
        {
            isMatch = false;
            discrepancies.Add(
                $"CveMetadata.DateUpdated mismatch: JSON = '{jsonMetadata["dateUpdated"]}', Model = '{metadata.DateUpdated?.ToString("yyyy-MM-dd HH:mm:ss")}'");
        }

        return isMatch;
    }

    private static bool VerifyContainers(JObject jsonContainers, Cve.Containers containers, List<string> discrepancies)
    {
        var isMatch = true;
        if (jsonContainers == null)
        {
            discrepancies.Add("Containers is missing in JSON but present in model");
            return false;
        }

        if (containers.Cna != null)
        {
            var jsonCna = jsonContainers["cna"] as JObject;
            isMatch &= VerifyCnaContainer(jsonCna, containers.Cna, discrepancies);
        }

        if (containers.Adp != null && containers.Adp.Count > 0)
        {
            var jsonAdp = jsonContainers["adp"] as JArray;
            if (jsonAdp == null || jsonAdp.Count != containers.Adp.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Containers.Adp count mismatch: JSON = '{jsonAdp?.Count ?? 0}', Model = '{containers.Adp.Count}'");
            }
            else
            {
                for (var i = 0; i < containers.Adp.Count; i++)
                    isMatch &= VerifyAdpContainer(jsonAdp[i] as JObject, containers.Adp[i], discrepancies, i);
            }
        }

        return isMatch;
    }

    private static bool VerifyCnaContainer(JObject jsonCna, Cve.CnaContainer cna, List<string> discrepancies)
    {
        var isMatch = true;
        if (jsonCna == null)
        {
            discrepancies.Add("CnaContainer is missing in JSON but present in model");
            return false;
        }

        if (jsonCna["title"]?.ToString() != cna.Title)
        {
            isMatch = false;
            discrepancies.Add($"Cna.Title mismatch: JSON = '{jsonCna["title"]}', Model = '{cna.Title}'");
        }

        // ProviderMetadata
        if (cna.ProviderMetadata != null)
        {
            var jsonProvider = jsonCna["providerMetadata"] as JObject;
            isMatch &= VerifyProviderMetadata(jsonProvider, cna.ProviderMetadata, discrepancies,
                "Cna.ProviderMetadata");
        }

        // ProblemTypes
        if (cna.ProblemTypes != null && cna.ProblemTypes.Count > 0)
        {
            var jsonProblems = jsonCna["problemTypes"] as JArray;
            if (jsonProblems == null || jsonProblems.Count != cna.ProblemTypes.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Cna.ProblemTypes count mismatch: JSON = '{jsonProblems?.Count ?? 0}', Model = '{cna.ProblemTypes.Count}'");
            }
            else
            {
                for (var i = 0; i < cna.ProblemTypes.Count; i++)
                {
                    var jsonProblem = jsonProblems[i] as JObject;
                    var descriptions = jsonProblem?["descriptions"] as JArray;
                    if (descriptions == null || descriptions.Count != cna.ProblemTypes[i].Descriptions?.Count)
                    {
                        isMatch = false;
                        discrepancies.Add(
                            $"Cna.ProblemTypes[{i}].Descriptions count mismatch: JSON = '{descriptions?.Count ?? 0}', Model = '{cna.ProblemTypes[i].Descriptions?.Count ?? 0}'");
                    }
                    else
                    {
                        for (var j = 0; j < cna.ProblemTypes[i].Descriptions.Count; j++)
                        {
                            var jsonDesc = descriptions[j];
                            var modelDesc = cna.ProblemTypes[i].Descriptions[j];
                            if (jsonDesc["cweId"]?.ToString() != modelDesc.CweId ||
                                jsonDesc["description"]?.ToString() != modelDesc.Description ||
                                jsonDesc["language"]?.ToString() != modelDesc.Language ||
                                jsonDesc["type"]?.ToString() != modelDesc.Type)
                            {
                                isMatch = false;
                                discrepancies.Add(
                                    $"Cna.ProblemTypes[{i}].Descriptions[{j}] mismatch: JSON = '{jsonDesc}', Model = 'CweId: {modelDesc.CweId}, Desc: {modelDesc.Description}, Lang: {modelDesc.Language}, Type: {modelDesc.Type}'");
                            }
                        }
                    }
                }
            }
        }

        // Affected
        if (cna.Affected != null && cna.Affected.Count > 0)
        {
            var jsonAffected = jsonCna["affected"] as JArray;
            if (jsonAffected == null || jsonAffected.Count != cna.Affected.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Cna.Affected count mismatch: JSON = '{jsonAffected?.Count ?? 0}', Model = '{cna.Affected.Count}'");
            }
            else
            {
                for (var i = 0; i < cna.Affected.Count; i++)
                    isMatch &= VerifyAffected(jsonAffected[i] as JObject, cna.Affected[i], discrepancies, i);
            }
        }

        // Descriptions
        if (cna.Descriptions != null && cna.Descriptions.Count > 0)
        {
            var jsonDescriptions = jsonCna["descriptions"] as JArray;
            if (jsonDescriptions == null || jsonDescriptions.Count != cna.Descriptions.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Cna.Descriptions count mismatch: JSON = '{jsonDescriptions?.Count ?? 0}', Model = '{cna.Descriptions.Count}'");
            }
            else
            {
                for (var i = 0; i < cna.Descriptions.Count; i++)
                {
                    var jsonDesc = jsonDescriptions[i];
                    var modelDesc = cna.Descriptions[i];
                    if (jsonDesc["language"]?.ToString() != modelDesc.Language ||
                        jsonDesc["value"]?.ToString() != modelDesc.DescriptionText)
                    {
                        isMatch = false;
                        discrepancies.Add(
                            $"Cna.Descriptions[{i}] mismatch: JSON = '{jsonDesc}', Model = 'Language: {modelDesc.Language}, Value: {modelDesc.DescriptionText}'");
                    }

                    // SupportingMedia（若有）
                    if (modelDesc.SupportingMedia != null && modelDesc.SupportingMedia.Count > 0)
                    {
                        var jsonMedia = jsonDesc["supportingMedia"] as JArray;
                        if (jsonMedia == null || jsonMedia.Count != modelDesc.SupportingMedia.Count)
                        {
                            isMatch = false;
                            discrepancies.Add(
                                $"Cna.Descriptions[{i}].SupportingMedia count mismatch: JSON = '{jsonMedia?.Count ?? 0}', Model = '{modelDesc.SupportingMedia.Count}'");
                        }
                        else
                        {
                            for (var j = 0; j < modelDesc.SupportingMedia.Count; j++)
                            {
                                var jsonSM = jsonMedia[j];
                                var modelSM = modelDesc.SupportingMedia[j];
                                if (jsonSM["language"]?.ToString() != modelSM.Language ||
                                    jsonSM["type"]?.ToString() != modelSM.Type ||
                                    jsonSM["base64"]?.ToString() != modelSM.Base64.ToString() ||
                                    jsonSM["value"]?.ToString() != modelSM.Value)
                                {
                                    isMatch = false;
                                    discrepancies.Add(
                                        $"Cna.Descriptions[{i}].SupportingMedia[{j}] mismatch: JSON = '{jsonSM}', Model = 'Lang: {modelSM.Language}, Type: {modelSM.Type}, Base64: {modelSM.Base64}, Value: {modelSM.Value}'");
                                }
                            }
                        }
                    }
                }
            }
        }

        // Metrics
        if (cna.Metrics != null && cna.Metrics.Count > 0)
        {
            var jsonMetrics = jsonCna["metrics"] as JArray;
            if (jsonMetrics == null || jsonMetrics.Count != cna.Metrics.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Cna.Metrics count mismatch: JSON = '{jsonMetrics?.Count ?? 0}', Model = '{cna.Metrics.Count}'");
            }
            else
            {
                for (var i = 0; i < cna.Metrics.Count; i++)
                {
                    var jsonMetric = jsonMetrics[i] as JObject;
                    var modelMetric = cna.Metrics[i];
                    if (modelMetric.CvssV4_0 != null)
                    {
                        var jsonCvss = jsonMetric["cvssV4_0"] as JObject;
                        if (jsonCvss == null ||
                            jsonCvss["baseScore"]?.ToString() != modelMetric.CvssV4_0.BaseScore.ToString() ||
                            jsonCvss["baseSeverity"]?.ToString() != modelMetric.CvssV4_0.BaseSeverity ||
                            jsonCvss["vectorString"]?.ToString() != modelMetric.CvssV4_0.VectorString)
                        {
                            isMatch = false;
                            discrepancies.Add(
                                $"Cna.Metrics[{i}].CvssV4_0 mismatch: JSON = '{jsonCvss}', Model = 'Score: {modelMetric.CvssV4_0.BaseScore}, Severity: {modelMetric.CvssV4_0.BaseSeverity}, Vector: {modelMetric.CvssV4_0.VectorString}'");
                        }
                    }

                    if (modelMetric.CvssV3_1 != null)
                    {
                        var jsonCvss = jsonMetric["cvssV3_1"] as JObject;
                        if (jsonCvss == null ||
                            jsonCvss["baseScore"]?.ToString() != modelMetric.CvssV3_1.BaseScore.ToString() ||
                            jsonCvss["baseSeverity"]?.ToString() != modelMetric.CvssV3_1.BaseSeverity ||
                            jsonCvss["vectorString"]?.ToString() != modelMetric.CvssV3_1.VectorString)
                        {
                            isMatch = false;
                            discrepancies.Add(
                                $"Cna.Metrics[{i}].CvssV3_1 mismatch: JSON = '{jsonCvss}', Model = 'Score: {modelMetric.CvssV3_1.BaseScore}, Severity: {modelMetric.CvssV3_1.BaseSeverity}, Vector: {modelMetric.CvssV3_1.VectorString}'");
                        }
                    }
                    // 同理檢查 CvssV3_0 和 CvssV2_0
                }
            }
        }

        // Timeline
        if (cna.Timeline != null && cna.Timeline.Count > 0)
        {
            var jsonTimeline = jsonCna["timeline"] as JArray;
            if (jsonTimeline == null || jsonTimeline.Count != cna.Timeline.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Cna.Timeline count mismatch: JSON = '{jsonTimeline?.Count ?? 0}', Model = '{cna.Timeline.Count}'");
            }
            else
            {
                for (var i = 0; i < cna.Timeline.Count; i++)
                {
                    var jsonEntry = jsonTimeline[i];
                    var modelEntry = cna.Timeline[i];
                    if (!CompareDateTime(jsonEntry["time"]?.ToString(), modelEntry.Time) ||
                        jsonEntry["language"]?.ToString() != modelEntry.Language ||
                        jsonEntry["value"]?.ToString() != modelEntry.Value)
                    {
                        isMatch = false;
                        discrepancies.Add(
                            $"Cna.Timeline[{i}] mismatch: JSON = '{jsonEntry}', Model = 'Time: {modelEntry.Time:yyyy-MM-dd HH:mm:ss}, Lang: {modelEntry.Language}, Value: {modelEntry.Value}'");
                    }
                }
            }
        }

        // Credits
        if (cna.Credits != null && cna.Credits.Count > 0)
        {
            var jsonCredits = jsonCna["credits"] as JArray;
            if (jsonCredits == null || jsonCredits.Count != cna.Credits.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Cna.Credits count mismatch: JSON = '{jsonCredits?.Count ?? 0}', Model = '{cna.Credits.Count}'");
            }
            else
            {
                for (var i = 0; i < cna.Credits.Count; i++)
                {
                    var jsonCredit = jsonCredits[i];
                    var modelCredit = cna.Credits[i];
                    if (jsonCredit["language"]?.ToString() != modelCredit.Language ||
                        jsonCredit["type"]?.ToString() != modelCredit.Type ||
                        jsonCredit["value"]?.ToString() != modelCredit.Value)
                    {
                        isMatch = false;
                        discrepancies.Add(
                            $"Cna.Credits[{i}] mismatch: JSON = '{jsonCredit}', Model = 'Lang: {modelCredit.Language}, Type: {modelCredit.Type}, Value: {modelCredit.Value}'");
                    }
                }
            }
        }

        // References
        if (cna.References != null && cna.References.Count > 0)
        {
            var jsonReferences = jsonCna["references"] as JArray;
            if (jsonReferences == null || jsonReferences.Count != cna.References.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Cna.References count mismatch: JSON = '{jsonReferences?.Count ?? 0}', Model = '{cna.References.Count}'");
            }
            else
            {
                for (var i = 0; i < cna.References.Count; i++)
                {
                    var jsonRef = jsonReferences[i];
                    var modelRef = cna.References[i];
                    if (jsonRef["url"]?.ToString() != modelRef.Url ||
                        jsonRef["name"]?.ToString() != modelRef.Name ||
                        !JToken.DeepEquals(jsonRef["tags"], JToken.FromObject(modelRef.Tags ?? new List<string>())))
                    {
                        isMatch = false;
                        discrepancies.Add(
                            $"Cna.References[{i}] mismatch: JSON = '{jsonRef}', Model = 'Url: {modelRef.Url}, Name: {modelRef.Name}, Tags: {string.Join(",", modelRef.Tags ?? new List<string>())}'");
                    }
                }
            }
        }

        return isMatch;
    }

    private static bool VerifyAffected(JObject jsonAffected, Cve.Affected affected, List<string> discrepancies,
        int index)
    {
        var isMatch = true;
        if (jsonAffected == null)
        {
            discrepancies.Add($"Cna.Affected[{index}] is missing in JSON but present in model");
            return false;
        }

        if (jsonAffected["vendor"]?.ToString() != affected.Vendor)
        {
            isMatch = false;
            discrepancies.Add(
                $"Cna.Affected[{index}].Vendor mismatch: JSON = '{jsonAffected["vendor"]}', Model = '{affected.Vendor}'");
        }

        if (jsonAffected["product"]?.ToString() != affected.Product)
        {
            isMatch = false;
            discrepancies.Add(
                $"Cna.Affected[{index}].Product mismatch: JSON = '{jsonAffected["product"]}', Model = '{affected.Product}'");
        }

        if (affected.Versions != null && affected.Versions.Count > 0)
        {
            var jsonVersions = jsonAffected["versions"] as JArray;
            if (jsonVersions == null || jsonVersions.Count != affected.Versions.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Cna.Affected[{index}].Versions count mismatch: JSON = '{jsonVersions?.Count ?? 0}', Model = '{affected.Versions.Count}'");
            }
            else
            {
                for (var i = 0; i < affected.Versions.Count; i++)
                {
                    var jsonVersion = jsonVersions[i];
                    var modelVersion = affected.Versions[i];
                    if (jsonVersion["version"]?.ToString() != modelVersion.VersionValue ||
                        jsonVersion["status"]?.ToString() != modelVersion.Status ||
                        jsonVersion["lessThanOrEqual"]?.ToString() != modelVersion.LessThanOrEqual ||
                        jsonVersion["versionType"]?.ToString() != modelVersion.VersionType)
                    {
                        isMatch = false;
                        discrepancies.Add(
                            $"Cna.Affected[{index}].Versions[{i}] mismatch: JSON = '{jsonVersion}', Model = 'Version: {modelVersion.VersionValue}, Status: {modelVersion.Status}, LTE: {modelVersion.LessThanOrEqual}, Type: {modelVersion.VersionType}'");
                    }
                }
            }
        }

        if (affected.Modules != null && affected.Modules.Count > 0)
        {
            var jsonModules = jsonAffected["modules"] as JArray;
            if (jsonModules == null || jsonModules.Count != affected.Modules.Count ||
                !jsonModules.Select(m => m.ToString()).SequenceEqual(affected.Modules))
            {
                isMatch = false;
                discrepancies.Add(
                    $"Cna.Affected[{index}].Modules mismatch: JSON = '{jsonModules}', Model = '{string.Join(",", affected.Modules)}'");
            }
        }

        return isMatch;
    }

    private static bool VerifyAdpContainer(JObject jsonAdp, Cve.AdpContainer adp, List<string> discrepancies, int index)
    {
        var isMatch = true;
        if (jsonAdp == null)
        {
            discrepancies.Add($"Containers.Adp[{index}] is missing in JSON but present in model");
            return false;
        }

        if (jsonAdp["title"]?.ToString() != adp.Title)
        {
            isMatch = false;
            discrepancies.Add(
                $"Containers.Adp[{index}].Title mismatch: JSON = '{jsonAdp["title"]}', Model = '{adp.Title}'");
        }

        if (adp.ProviderMetadata != null)
        {
            var jsonProvider = jsonAdp["providerMetadata"] as JObject;
            isMatch &= VerifyProviderMetadata(jsonProvider, adp.ProviderMetadata, discrepancies,
                $"Containers.Adp[{index}].ProviderMetadata");
        }

        if (adp.Metrics != null && adp.Metrics.Count > 0)
        {
            var jsonMetrics = jsonAdp["metrics"] as JArray;
            if (jsonMetrics == null || jsonMetrics.Count != adp.Metrics.Count)
            {
                isMatch = false;
                discrepancies.Add(
                    $"Containers.Adp[{index}].Metrics count mismatch: JSON = '{jsonMetrics?.Count ?? 0}', Model = '{adp.Metrics.Count}'");
            }
            else
            {
                for (var i = 0; i < adp.Metrics.Count; i++)
                {
                    var jsonMetric = jsonMetrics[i] as JObject;
                    var modelMetric = adp.Metrics[i];
                    if (modelMetric.Other != null && modelMetric.Other.Content != null)
                    {
                        var jsonOther = jsonMetric["other"] as JObject;
                        if (jsonOther == null || jsonOther["type"]?.ToString() != modelMetric.Other.Type)
                        {
                            isMatch = false;
                            discrepancies.Add(
                                $"Containers.Adp[{index}].Metrics[{i}].Other.Type mismatch: JSON = '{jsonOther?["type"]}', Model = '{modelMetric.Other.Type}'");
                        }

                        var jsonContent = jsonOther?["content"] as JObject;
                        if (jsonContent != null && modelMetric.Other.Content != null)
                        {
                            if (jsonContent["id"]?.ToString() != modelMetric.Other.Content.Id ||
                                jsonContent["timestamp"]?.ToString() !=
                                modelMetric.Other.Content.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss") ||
                                jsonContent["version"]?.ToString() != modelMetric.Other.Content.Version ||
                                jsonContent["role"]?.ToString() != modelMetric.Other.Content.Role)
                            {
                                isMatch = false;
                                discrepancies.Add(
                                    $"Containers.Adp[{index}].Metrics[{i}].Other.Content mismatch: JSON = '{jsonContent}', Model = 'Id: {modelMetric.Other.Content.Id}, TS: {modelMetric.Other.Content.Timestamp:yyyy-MM-ddTHH:mm:ss}, Ver: {modelMetric.Other.Content.Version}, Role: {modelMetric.Other.Content.Role}'");
                            }

                            if (modelMetric.Other.Content.Options != null &&
                                modelMetric.Other.Content.Options.Count > 0)
                            {
                                var jsonOptions = jsonContent["options"] as JArray;
                                if (jsonOptions == null || jsonOptions.Count != modelMetric.Other.Content.Options.Count)
                                {
                                    isMatch = false;
                                    discrepancies.Add(
                                        $"Containers.Adp[{index}].Metrics[{i}].Other.Content.Options count mismatch: JSON = '{jsonOptions?.Count ?? 0}', Model = '{modelMetric.Other.Content.Options.Count}'");
                                }
                                else
                                {
                                    for (var j = 0; j < modelMetric.Other.Content.Options.Count; j++)
                                    {
                                        var jsonOption = jsonOptions[j];
                                        var modelOption = modelMetric.Other.Content.Options[j];
                                        if (jsonOption["exploitation"]?.ToString() != modelOption.Exploitation ||
                                            jsonOption["automatable"]?.ToString() != modelOption.Automatable ||
                                            jsonOption["technicalImpact"]?.ToString() != modelOption.TechnicalImpact)
                                        {
                                            isMatch = false;
                                            discrepancies.Add(
                                                $"Containers.Adp[{index}].Metrics[{i}].Other.Content.Options[{j}] mismatch: JSON = '{jsonOption}', Model = 'Exp: {modelOption.Exploitation}, Auto: {modelOption.Automatable}, TI: {modelOption.TechnicalImpact}'");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return isMatch;
    }

    private static bool VerifyProviderMetadata(JObject jsonProvider, Cve.ProviderMetadata provider,
        List<string> discrepancies, string context)
    {
        var isMatch = true;
        if (jsonProvider == null)
        {
            discrepancies.Add($"{context} is missing in JSON but present in model");
            return false;
        }

        if (jsonProvider["orgId"]?.ToString() != provider.OrgId)
        {
            isMatch = false;
            discrepancies.Add(
                $"{context}.OrgId mismatch: JSON = '{jsonProvider["orgId"]}', Model = '{provider.OrgId}'");
        }

        if (jsonProvider["shortName"]?.ToString() != provider.ShortName)
        {
            isMatch = false;
            discrepancies.Add(
                $"{context}.ShortName mismatch: JSON = '{jsonProvider["shortName"]}', Model = '{provider.ShortName}'");
        }

        if (!CompareDateTime(jsonProvider["dateUpdated"]?.ToString(), provider.DateUpdated))
        {
            isMatch = false;
            discrepancies.Add(
                $"{context}.DateUpdated mismatch: JSON = '{jsonProvider["dateUpdated"]}', Model = '{provider.DateUpdated?.ToString("yyyy-MM-dd HH:mm:ss")}'");
        }

        return isMatch;
    }

    // 時間比較輔助方法
    private static bool CompareDateTime(string jsonDateTime, DateTime? modelDateTime)
    {
        if (string.IsNullOrEmpty(jsonDateTime) && !modelDateTime.HasValue) return true; // 兩者都為 null，視為相等
        if (string.IsNullOrEmpty(jsonDateTime) || !modelDateTime.HasValue) return false; // 一方為 null，另一方有值，不相等

        // 解析 JSON 中的時間字串
        if (DateTime.TryParse(jsonDateTime, out var parsedJsonDateTime))
        {
            // 確保兩者都轉換為 UTC 進行比較
            var jsonUtc = parsedJsonDateTime.Kind == DateTimeKind.Unspecified
                ? DateTime.SpecifyKind(parsedJsonDateTime, DateTimeKind.Utc)
                : parsedJsonDateTime.ToUniversalTime();
            var modelUtc = modelDateTime.Value.ToUniversalTime();

            // 比較時間值（忽略毫秒以下的差異，根據需求可調整）
            return jsonUtc == modelUtc;
        }

        return false; // 無法解析 JSON 時間，視為不匹配
    }
}