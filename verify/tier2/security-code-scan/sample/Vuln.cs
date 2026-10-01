using System.Security.Cryptography;

// Known-vulnerable sample for the Tier-2 verification harness.
// Security Code Scan should report SCS0006 (weak hashing function) for MD5 —
// a pattern-based rule needing no NuGet packages or taint source, so it fires
// deterministically on a dependency-free project.
public class Vuln
{
    public byte[] Hash(byte[] data)
    {
        using (var md5 = MD5.Create())
        {
            return md5.ComputeHash(data);
        }
    }
}
