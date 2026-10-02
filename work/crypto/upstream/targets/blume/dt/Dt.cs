// dt: double columnar transposition solver (simulated annealing on Spanish quadgrams), multithreaded.
// Build: csc.exe /o+ /out:dt.exe Dt.cs
//
// Usage:
//   dt.exe solve  CTFILE W1MIN W1MAX W2MIN W2MAX SAME(0|1) RESTARTS ITERS THREADS [SEED]
//   dt.exe plant  PLAINFILE OFFSET LEN W1 W2 SAME(0|1) RESTARTS ITERS THREADS SEED
//
// Convention (matches blume/trans.py): plaintext written in rows of width W, the last row possibly short;
// columns read top to bottom in key order (order[k] = column read k-th). Double = apply twice (key1 then key2).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

static class Dt
{
    static float[] Q;
    const float PERQ_SPANISH = -4.1f;

    static void LoadQ()
    {
        var bytes = File.ReadAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "q4_es.bin"));
        Q = new float[bytes.Length / 4];
        Buffer.BlockCopy(bytes, 0, Q, 0, bytes.Length);
    }

    // map[i] = position in the transposed text that holds plaintext position i
    static void ColMap(int n, int[] order, int w, int[] map)
    {
        int rows = n / w, rem = n % w;
        int pos = 0;
        for (int k = 0; k < w; k++)
        {
            int c = order[k]; int L = rows + (c < rem ? 1 : 0);
            for (int r = 0; r < L; r++) map[r * w + c] = pos++;
        }
    }

    static double Score(int[] ct, int n, int[] o1, int w1, int[] o2, int w2, bool same, int[] m1, int[] m2, int[] buf)
    {
        ColMap(n, o1, w1, m1);
        if (same) ColMap(n, o1, w1, m2); else ColMap(n, o2, w2, m2);
        // plaintext i -> intermediate m1[i] -> ciphertext m2[m1[i]]
        for (int i = 0; i < n; i++) buf[i] = ct[m2[m1[i]]];
        double s = 0; int code = buf[0] * 17576 + buf[1] * 676 + buf[2] * 26 + buf[3];
        s += Q[code];
        for (int i = 4; i < n; i++) { code = (code % 17576) * 26 + buf[i]; s += Q[code]; }
        return s;
    }

    static void Mutate(int[] src, int[] dst, int w, Random rnd)
    {
        Array.Copy(src, dst, w);
        int r = rnd.Next(100);
        if (r < 40) { int a = rnd.Next(w), b = rnd.Next(w); int t = dst[a]; dst[a] = dst[b]; dst[b] = t; }
        else if (r < 75)
        {   // move a block
            int a = rnd.Next(w), len = 1 + rnd.Next(Math.Max(1, w / 2)); if (a + len > w) len = w - a;
            var blk = new int[len]; Array.Copy(src, a, blk, 0, len);
            var rest = new List<int>(); for (int i = 0; i < w; i++) if (i < a || i >= a + len) rest.Add(src[i]);
            int ins = rnd.Next(rest.Count + 1); rest.InsertRange(ins, blk); rest.CopyTo(dst);
        }
        else if (r < 90) { int a = rnd.Next(w), b = rnd.Next(w); if (a > b) { int t = a; a = b; b = t; } Array.Reverse(dst, a, b - a + 1); }
        else { int k = 1 + rnd.Next(w - 1); for (int i = 0; i < w; i++) dst[i] = src[(i + k) % w]; }
    }

    static int[] RandPerm(int w, Random rnd) { var p = Enumerable.Range(0, w).ToArray(); for (int i = w - 1; i > 0; i--) { int j = rnd.Next(i + 1); int t = p[i]; p[i] = p[j]; p[j] = t; } return p; }

    class Result { public double Score; public int[] O1, O2; public int W1, W2; }

    static Result Anneal(int[] ct, int n, int w1, int w2, bool same, long iters, Random rnd)
    {
        int[] m1 = new int[n], m2 = new int[n], buf = new int[n];
        int[] o1 = RandPerm(w1, rnd), o2 = same ? o1 : RandPerm(w2, rnd);
        int[] c1 = new int[w1], c2 = new int[same ? w1 : w2];
        double cur = Score(ct, n, o1, w1, o2, w2, same, m1, m2, buf);
        var best = new Result { Score = cur, O1 = (int[])o1.Clone(), O2 = (int[])o2.Clone(), W1 = w1, W2 = w2 };
        double T0 = 25.0, T1 = 0.4;
        for (long it = 0; it < iters; it++)
        {
            double T = T0 * Math.Pow(T1 / T0, (double)it / iters);
            bool first = same || rnd.Next(2) == 0;
            double v;
            if (first) { Mutate(o1, c1, w1, rnd); v = Score(ct, n, c1, w1, same ? c1 : o2, w2, same, m1, m2, buf); }
            else { Mutate(o2, c2, w2, rnd); v = Score(ct, n, o1, w1, c2, w2, same, m1, m2, buf); }
            if (v >= cur || rnd.NextDouble() < Math.Exp((v - cur) / T))
            {
                cur = v;
                if (first) { var t = o1; o1 = c1; c1 = t; if (same) o2 = o1; } else { var t = o2; o2 = c2; c2 = t; }
                if (cur > best.Score) { best.Score = cur; best.O1 = (int[])o1.Clone(); best.O2 = (int[])o2.Clone(); }
            }
        }
        return best;
    }

    static string Decrypt(int[] ct, int n, Result r, bool same)
    {
        int[] m1 = new int[n], m2 = new int[n], buf = new int[n];
        Score(ct, n, r.O1, r.W1, r.O2, r.W2, same, m1, m2, buf);
        var sb = new StringBuilder(); foreach (var x in buf) sb.Append((char)('a' + x)); return sb.ToString();
    }

    static int[] Encrypt(int[] pt, int n, int[] o, int w)
    {
        int[] map = new int[n]; ColMap(n, o, w, map); int[] ct = new int[n];
        for (int i = 0; i < n; i++) ct[map[i]] = pt[i]; return ct;
    }

    static List<Result> Solve(int[] ct, int w1min, int w1max, int w2min, int w2max, bool same, int restarts, long iters, int threads, int seed)
    {
        int n = ct.Length;
        var jobs = new List<Tuple<int, int, int>>();
        for (int a = w1min; a <= w1max; a++)
            for (int b = same ? a : w2min; b <= (same ? a : w2max); b++)
                for (int r = 0; r < restarts; r++) jobs.Add(Tuple.Create(a, b, r));
        var best = new Dictionary<string, Result>();
        object lk = new object();
        int done = 0;
        Parallel.ForEach(jobs, new ParallelOptions { MaxDegreeOfParallelism = threads }, job =>
        {
            var rnd = new Random(seed * 1000003 + job.Item1 * 1009 + job.Item2 * 31 + job.Item3);
            var res = Anneal(ct, n, job.Item1, job.Item2, same, iters, rnd);
            string key = job.Item1 + "/" + job.Item2;
            lock (lk)
            {
                Result prev; if (!best.TryGetValue(key, out prev) || res.Score > prev.Score) best[key] = res;
                done++;
            }
        });
        return best.Values.OrderByDescending(r => r.Score).ToList();
    }

    static int[] ToInts(string s) { return s.Where(ch => ch >= 'a' && ch <= 'z').Select(ch => ch - 'a').ToArray(); }

    static void Main(string[] a)
    {
        LoadQ();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        if (a[0] == "solve")
        {
            int[] ct = ToInts(File.ReadAllText(a[1]).ToLower());
            bool same = a[6] == "1";
            var res = Solve(ct, int.Parse(a[2]), int.Parse(a[3]), int.Parse(a[4]), int.Parse(a[5]), same, int.Parse(a[7]), long.Parse(a[8]), int.Parse(a[9]), a.Length > 10 ? int.Parse(a[10]) : 1);
            int n = ct.Length;
            foreach (var r in res.Take(15))
                Console.WriteLine("{0,2}/{1,2} {2:F3} {3}", r.W1, r.W2, r.Score / (n - 3), Decrypt(ct, n, r, same).Substring(0, 70));
            var top = res[0];
            Console.WriteLine("BEST {0}/{1} {2:F3}\n{3}\nkey1 {4}\nkey2 {5}", top.W1, top.W2, top.Score / (n - 3), Decrypt(ct, n, top, same), string.Join(",", top.O1), string.Join(",", top.O2));
        }
        else
        {
            var text = ToInts(File.ReadAllText(a[1]).ToLower());
            int off = int.Parse(a[2]), len = int.Parse(a[3]), w1 = int.Parse(a[4]), w2 = int.Parse(a[5]);
            bool same = a[6] == "1"; int restarts = int.Parse(a[7]); long iters = long.Parse(a[8]); int threads = int.Parse(a[9]); int seed = int.Parse(a[10]);
            var pt = text.Skip(off).Take(len).ToArray();
            var rnd = new Random(seed);
            int[] k1 = RandPerm(w1, rnd), k2 = same ? k1 : RandPerm(w2, rnd);
            var ct = Encrypt(Encrypt(pt, len, k1, w1), len, k2, same ? w1 : w2);
            var res = Solve(ct, w1, w1, same ? w1 : w2, same ? w1 : w2, same, restarts, iters, threads, seed + 7);
            var r0 = res[0];
            string dec = Decrypt(ct, len, r0, same);
            int ok = 0; for (int i = 0; i < len; i++) if (dec[i] - 'a' == pt[i]) ok++;
            int[] m1 = new int[len], m2 = new int[len], buf = new int[len];
            var truth = new Result { O1 = k1, O2 = k2, W1 = w1, W2 = same ? w1 : w2 };
            double ts = Score(ct, len, k1, w1, k2, truth.W2, same, m1, m2, buf);
            Console.WriteLine("plant {0}/{1} same={2}: best {3:F3}, true key {4:F3}, letters right {5}/{6}  {7}", w1, w2, same, r0.Score / (len - 3), ts / (len - 3), ok, len, dec.Substring(0, 50));
        }
        Console.WriteLine("elapsed {0:F1}s", sw.Elapsed.TotalSeconds);
    }
}

