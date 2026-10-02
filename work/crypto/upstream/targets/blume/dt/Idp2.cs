// idp2: faster divide-and-conquer attack on double columnar transposition (after Lasry, Kopal & Wacker 2014).
// Stage 1: hill-climb / anneal key2 alone, scored by IDP (undo key2; the intermediate text is the first
//          transposition's column readout; row-aligned pairs of those columns should be good Spanish bigrams).
//          Offsets of column starts (unequal column lengths) are enumerated within +-TOL of their expectation.
// Stage 2: for the top key2 candidates, solve key1 as a single columnar transposition on quadgrams.
// Build: csc.exe /o+ /out:idp2.exe Idp2.cs
// Usage: idp2.exe plant PLAINFILE OFFSET LEN W1 W2 RESTARTS ITERS THREADS SEED
//        idp2.exe solve CTFILE W1MIN W1MAX W2MIN W2MAX RESTARTS ITERS THREADS SEED
//        idp2.exe bench W1 W2
// Env: IDP_TOL (default 2), IDP_MODE=hc|sa (default sa), IDP_TOP (candidates to stage 2, default 24)
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

static class Idp2
{
    static float[] Q4; static int[] B2; // B2 scaled by 1000
    static int TOL = 2; static string MODE = "sa"; static int TOP = 24; static bool MATCH = Environment.GetEnvironmentVariable("IDP_MATCH") == "1"; static int INVM = Environment.GetEnvironmentVariable("IDP_INV") == null ? 0 : int.Parse(Environment.GetEnvironmentVariable("IDP_INV")); static bool INV = INVM == 1 || INVM == 2;
    [ThreadStatic] static int[] SM; [ThreadStatic] static long[] Hu, Hv; [ThreadStatic] static int[] Hp, Hway;

    static void Load()
    {
        var bytes = File.ReadAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "q4_es.bin"));
        Q4 = new float[bytes.Length / 4]; Buffer.BlockCopy(bytes, 0, Q4, 0, bytes.Length);
        var cnt = new double[676];
        for (int c = 0; c < Q4.Length; c++) { double p = Math.Pow(10, Q4[c]); cnt[c / 676] += p; }
        double tot = cnt.Sum(); B2 = new int[676];
        for (int i = 0; i < 676; i++) B2[i] = (int)Math.Round(1000 * Math.Log10(Math.Max(cnt[i] / tot, 1e-7)));
        var e = Environment.GetEnvironmentVariable("IDP_TOL"); if (e != null) TOL = int.Parse(e);
        e = Environment.GetEnvironmentVariable("IDP_MODE"); if (e != null) MODE = e;
        e = Environment.GetEnvironmentVariable("IDP_TOP"); if (e != null) TOP = int.Parse(e);
    }

    static void ColMap(int n, int[] order, int w, int[] map)
    {
        int rows = n / w, rem = n % w, pos = 0;
        for (int k = 0; k < w; k++) { int c = order[k]; int L = rows + (c < rem ? 1 : 0); for (int r = 0; r < L; r++) map[r * w + c] = pos++; }
    }
    static int[] RandPerm(int w, Random rnd) { var p = Enumerable.Range(0, w).ToArray(); for (int i = w - 1; i > 0; i--) { int j = rnd.Next(i + 1); int t = p[i]; p[i] = p[j]; p[j] = t; } return p; }

    static void Mutate(int[] src, int[] dst, int w, Random rnd)
    {
        Array.Copy(src, dst, w); int r = rnd.Next(100);
        if (r < 45) { int a = rnd.Next(w), b = rnd.Next(w); int t = dst[a]; dst[a] = dst[b]; dst[b] = t; }
        else if (r < 80)
        {
            int a = rnd.Next(w), len = 1 + rnd.Next(Math.Max(1, w / 2)); if (a + len > w) len = w - a;
            var rest = new List<int>(w); for (int i = 0; i < w; i++) if (i < a || i >= a + len) rest.Add(src[i]);
            var blk = new int[len]; Array.Copy(src, a, blk, 0, len); rest.InsertRange(rnd.Next(rest.Count + 1), blk); rest.CopyTo(dst);
        }
        else { int a = rnd.Next(w), b = rnd.Next(w); if (a > b) { int t = a; a = b; b = t; } Array.Reverse(dst, a, b - a + 1); }
    }

    // Precomputed geometry for IDP at width w1
    class Geo
    {
        public int w1, rows, rem; public int[] a, b; // offset ranges per read-index k
        public Geo(int n, int w1)
        {
            this.w1 = w1; rows = n / w1; rem = n % w1; a = new int[w1]; b = new int[w1];
            for (int k = 0; k < w1; k++)
            {
                double e = (double)k * rem / w1; int lo = Math.Max(0, k - (w1 - rem)), hi = Math.Min(k, rem);
                a[k] = Math.Max(lo, (int)Math.Round(e) - TOL); b[k] = Math.Min(hi, (int)Math.Round(e) + TOL);
            }
        }
    }

    static double IdpScore(int[] I, Geo g)
    {
        int w1 = g.w1, rows = g.rows; long total = 0;
        if (INV)
        {
            int n = I.Length; for (int p = 0; p + w1 < n; p++) total += B2[I[p] * 26 + I[p + w1]];
            return total / (1000.0 * (n - w1));
        }
        int[] A = g.a, Bb = g.b;
        for (int k1 = 0; k1 < w1; k1++)
        {
            int best = int.MinValue; int a1 = A[k1], b1 = Bb[k1]; int base1 = k1 * rows;
            if (MATCH && (SM == null || SM.Length < w1 * w1)) SM = new int[w1 * w1];
            for (int k2 = 0; k2 < w1; k2++)
            {
                if (k2 == k1) { if (MATCH) SM[k1 * w1 + k2] = -100000000; continue; }
                int pbest = int.MinValue;
                int a2 = A[k2], b2 = Bb[k2]; int base2 = k2 * rows;
                for (int d = a2 - b1; d <= b2 - a1; d++)
                {
                    int tmin = Math.Max(a1, a2 - d), tmax = Math.Min(b1, b2 - d); if (tmin > tmax) continue;
                    // window sum for u1 = tmin
                    int s = 0; int p1 = base1 + tmin, p2 = base2 + d + tmin;
                    for (int r = 0; r < rows; r++) s += B2[I[p1 + r] * 26 + I[p2 + r]];
                    if (s > pbest) pbest = s;
                    for (int u = tmin + 1; u <= tmax; u++)
                    {
                        s += B2[I[p1 + rows] * 26 + I[p2 + rows]] - B2[I[p1] * 26 + I[p2]];
                        p1++; p2++;
                        if (s > pbest) pbest = s;
                    }
                }
                if (MATCH) SM[k1 * w1 + k2] = pbest;
                if (pbest > best) best = pbest;
            }
            total += best;
        }
        if (MATCH) total = Assign(SM, w1);
        return total / (1000.0 * w1 * rows);
    }

    // maximum-weight perfect matching on an n x n score matrix (Hungarian algorithm on negated scores)
    static long Assign(int[] S, int n)
    {
        if (Hu == null || Hu.Length < n + 1) { Hu = new long[n + 1]; Hv = new long[n + 1]; Hp = new int[n + 1]; Hway = new int[n + 1]; }
        var u = Hu; var v = Hv; var p = Hp; var way = Hway;
        for (int i = 0; i <= n; i++) { u[i] = 0; v[i] = 0; p[i] = 0; way[i] = 0; }
        var minv = new long[n + 1]; var used = new bool[n + 1];
        const long INF = long.MaxValue / 4;
        for (int i = 1; i <= n; i++)
        {
            p[0] = i; int j0 = 0;
            for (int j = 0; j <= n; j++) { minv[j] = INF; used[j] = false; }
            do
            {
                used[j0] = true; int i0 = p[j0]; long delta = INF; int j1 = 0;
                for (int j = 1; j <= n; j++) if (!used[j])
                {
                    long cur = -(long)S[(i0 - 1) * n + (j - 1)] - u[i0] - v[j];
                    if (cur < minv[j]) { minv[j] = cur; way[j] = j0; }
                    if (minv[j] < delta) { delta = minv[j]; j1 = j; }
                }
                for (int j = 0; j <= n; j++) { if (used[j]) { u[p[j]] += delta; v[j] -= delta; } else minv[j] -= delta; }
                j0 = j1;
            } while (p[j0] != 0);
            do { int j1 = way[j0]; p[j0] = p[j1]; j0 = j1; } while (j0 != 0);
        }
        long tot = 0; for (int j = 1; j <= n; j++) tot += S[(p[j] - 1) * n + (j - 1)];
        return tot;
    }

    static double Q4Score(int[] t, int n)
    {
        int code = t[0] * 17576 + t[1] * 676 + t[2] * 26 + t[3]; double s = Q4[code];
        for (int i = 4; i < n; i++) { code = (code % 17576) * 26 + t[i]; s += Q4[code]; }
        return s / (n - 3);
    }

    class Cand { public double Score; public int[] K2; public int W1, W2; }

    static Cand SearchK2(int[] ct, int n, int w1, int w2, long iters, Random rnd)
    {
        var g = new Geo(n, w1);
        int[] map = new int[n], I = new int[n];
        int[] o = RandPerm(w2, rnd), c = new int[w2];
        Func<int[], double> f = k => { var J = UndoK2(ct, n, k, w2); Array.Copy(J, I, n); return IdpScore(I, g); };
        double cur = f(o); var best = new Cand { Score = cur, K2 = (int[])o.Clone(), W1 = w1, W2 = w2 };
        if (MODE == "hc")
        {
            long used = 0;
            while (used < iters)
            {
                bool improved = true;
                while (improved && used < iters)
                {
                    improved = false;
                    for (int i = 0; i < w2 && used < iters; i++) for (int j = i + 1; j < w2 && used < iters; j++)
                    {
                        Array.Copy(o, c, w2); int t = c[i]; c[i] = c[j]; c[j] = t;
                        double v = f(c); used++;
                        if (v > cur) { cur = v; int[] tt = o; o = c; c = tt; improved = true; }
                        else { Array.Copy(o, c, w2); Array.Reverse(c, i, j - i + 1); v = f(c); used++; if (v > cur) { cur = v; int[] tt = o; o = c; c = tt; improved = true; } }
                    }
                }
                if (cur > best.Score) { best.Score = cur; best.K2 = (int[])o.Clone(); }
                o = RandPerm(w2, rnd); cur = f(o); used++;
            }
            return best;
        }
        double T0 = 0.05, T1 = 0.001;
        for (long it = 0; it < iters; it++)
        {
            double T = T0 * Math.Pow(T1 / T0, (double)it / iters);
            Mutate(o, c, w2, rnd); double v = f(c);
            if (v >= cur || rnd.NextDouble() < Math.Exp((v - cur) / T)) { cur = v; var t = o; o = c; c = t; if (cur > best.Score) { best.Score = cur; best.K2 = (int[])o.Clone(); } }
        }
        return best;
    }

    static Tuple<double, int[]> SolveK1(int[] I, int n, int w1, long iters, Random rnd)
    {
        int[] map = new int[n], P = new int[n];
        int[] o = RandPerm(w1, rnd), c = new int[w1];
        Func<int[], double> f = k => { var J = UndoK1(I, n, k, w1); Array.Copy(J, P, n); return Q4Score(P, n); };
        double cur = f(o); double bestS = cur; int[] bestK = (int[])o.Clone();
        double T0 = 0.04, T1 = 0.0008;
        for (long it = 0; it < iters; it++)
        {
            double T = T0 * Math.Pow(T1 / T0, (double)it / iters);
            Mutate(o, c, w1, rnd); double v = f(c);
            if (v >= cur || rnd.NextDouble() < Math.Exp((v - cur) / T)) { cur = v; var t = o; o = c; c = t; if (cur > bestS) { bestS = cur; bestK = (int[])o.Clone(); } }
        }
        return Tuple.Create(bestS, bestK);
    }

    static int[] Encrypt(int[] pt, int n, int[] o, int w) { int[] map = new int[n]; ColMap(n, o, w, map); int[] ct = new int[n]; for (int i = 0; i < n; i++) ct[map[i]] = pt[i]; return ct; }
    static int[] UndoF(int[] ct, int n, int[] o, int w) { int[] map = new int[n]; ColMap(n, o, w, map); int[] I = new int[n]; for (int i = 0; i < n; i++) I[i] = ct[map[i]]; return I; }
    // conventions: 0 = F.F (rows written, columns read, twice); 1 = G.G (columns written, rows read, twice); 2 = G first then F
    // 3 = F first (rows written, columns read) then G (columns written, rows read); the intermediate is a column readout, so the IDP score applies
    static int[] UndoK2(int[] ct, int n, int[] o, int w) { return (INVM == 1 || INVM == 3) ? Encrypt(ct, n, o, w) : UndoF(ct, n, o, w); }
    static int[] UndoK1(int[] I, int n, int[] o, int w) { return (INVM == 1 || INVM == 2) ? Encrypt(I, n, o, w) : UndoF(I, n, o, w); }
    static int[] EncK1(int[] pt, int n, int[] o, int w) { return (INVM == 1 || INVM == 2) ? UndoF(pt, n, o, w) : Encrypt(pt, n, o, w); }
    static int[] EncK2(int[] I, int n, int[] o, int w) { return (INVM == 1 || INVM == 3) ? UndoF(I, n, o, w) : Encrypt(I, n, o, w); }
    static int[] ToInts(string s) { return s.ToLower().Where(ch => ch >= 'a' && ch <= 'z').Select(ch => ch - 'a').ToArray(); }
    static string Str(int[] a, int len) { var sb = new StringBuilder(); for (int i = 0; i < Math.Min(len, a.Length); i++) sb.Append((char)('a' + a[i])); return sb.ToString(); }

    static void Run(int[] ct, int[] pt, int w1min, int w1max, int w2min, int w2max, int restarts, long iters, int threads, int seed, int[] trueK2)
    {
        int n = ct.Length;
        var jobs = new List<Tuple<int, int, int>>();
        for (int a = w1min; a <= w1max; a++) for (int b = w2min; b <= w2max; b++) for (int r = 0; r < restarts; r++) jobs.Add(Tuple.Create(a, b, r));
        var cands = new List<Cand>(); object lk = new object(); int done = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Parallel.ForEach(jobs, new ParallelOptions { MaxDegreeOfParallelism = threads }, j =>
        {
            var res = SearchK2(ct, n, j.Item1, j.Item2, iters, new Random(seed * 7919 + j.Item1 * 101 + j.Item2 * 13 + j.Item3));
            lock (lk)
            {
                cands.Add(res); done++;
                string hit = trueK2 != null && res.K2.SequenceEqual(trueK2) ? " TRUE-KEY2" : "";
                Console.Error.WriteLine("stage1 {0}/{1} w1={2} w2={3} idp {4:F4}{5} {6:F0}s", done, jobs.Count, res.W1, res.W2, res.Score, hit, sw.Elapsed.TotalSeconds);
            }
        });
        var top = cands.OrderByDescending(c => c.Score).GroupBy(c => c.W1 + "/" + c.W2 + ":" + string.Join(",", c.K2)).Select(gr => gr.First()).Take(TOP).ToList();
        Console.WriteLine("stage1 top idp: " + string.Join("  ", top.Take(10).Select(c => c.W1 + "/" + c.W2 + " " + c.Score.ToString("F4"))));
        var finals = new List<Tuple<double, Cand, int[]>>();
        Parallel.ForEach(top, new ParallelOptions { MaxDegreeOfParallelism = threads }, c =>
        {
            var I = UndoK2(ct, n, c.K2, c.W2);
            Tuple<double, int[]> best = null;
            for (int r = 0; r < 4; r++) { var s = SolveK1(I, n, c.W1, 2000000, new Random(seed + r * 17 + c.K2[0] + 31 * c.W1)); if (best == null || s.Item1 > best.Item1) best = s; }
            lock (lk) finals.Add(Tuple.Create(best.Item1, c, best.Item2));
        });
        foreach (var f in finals.OrderByDescending(x => x.Item1).Take(10))
        {
            var I = UndoK2(ct, n, f.Item2.K2, f.Item2.W2); var P = UndoK1(I, n, f.Item3, f.Item2.W1);
            string acc = ""; if (pt != null) { int ok = 0; for (int i = 0; i < n; i++) if (P[i] == pt[i]) ok++; acc = " right " + ok + "/" + n; }
            Console.WriteLine("{0}/{1} idp {2:F4} q4 {3:F3}{4}  {5}", f.Item2.W1, f.Item2.W2, f.Item2.Score, f.Item1, acc, Str(P, 80));
            Console.WriteLine("   key1 {0}\n   key2 {1}", string.Join(",", f.Item3), string.Join(",", f.Item2.K2));
        }
        var bestF = finals.OrderByDescending(x => x.Item1).First();
        Console.WriteLine("FULL " + Str(UndoK1(UndoK2(ct, n, bestF.Item2.K2, bestF.Item2.W2), n, bestF.Item3, bestF.Item2.W1), n));
    }

    // exhaustive enumeration of key2 (w2! permutations, Heap's algorithm); returns the top K candidates by IDP
    static List<Cand> ExhaustK2(int[] ct, int n, int w1, int w2, int keep, int[] trueK2)
    {
        var g = new Geo(n, w1); int[] map = new int[n], I = new int[n];
        var top = new List<Cand>(); double worst = double.NegativeInfinity; long cnt = 0; int trueRank = -1; double trueScore = double.NaN;
        var perm = Enumerable.Range(0, w2).ToArray(); var cc = new int[w2];
        Action eval = () =>
        {
            var J = UndoK2(ct, n, perm, w2); Array.Copy(J, I, n); double s = IdpScore(I, g); cnt++;
            if (trueK2 != null && perm.SequenceEqual(trueK2)) trueScore = s;
            if (top.Count < keep || s > worst)
            {
                top.Add(new Cand { Score = s, K2 = (int[])perm.Clone(), W1 = w1, W2 = w2 });
                if (top.Count > keep) { int mi = 0; for (int i = 1; i < top.Count; i++) if (top[i].Score < top[mi].Score) mi = i; top.RemoveAt(mi); }
                worst = top.Min(t => t.Score);
            }
        };
        eval(); int k = 0;
        while (k < w2)
        {
            if (cc[k] < k)
            {
                if (k % 2 == 0) { int t = perm[0]; perm[0] = perm[k]; perm[k] = t; } else { int t = perm[cc[k]]; perm[cc[k]] = perm[k]; perm[k] = t; }
                eval(); cc[k]++; k = 0;
            }
            else { cc[k] = 0; k++; }
        }
        if (trueK2 != null) { trueRank = top.Count(t => t.Score > trueScore); Console.Error.WriteLine("exhaust w1={0} w2={1}: {2} perms, true key2 idp {3:F4}, better candidates {4}, best {5:F4}", w1, w2, cnt, trueScore, trueRank, top.Max(t => t.Score)); }
        return top.OrderByDescending(t => t.Score).ToList();
    }

    static void RunExhaust(int[] ct, int[] pt, int w1min, int w1max, int w2min, int w2max, int keep, int threads, int seed, int[] trueK2)
    {
        int n = ct.Length; var pairs = new List<Tuple<int, int>>();
        for (int b = w2min; b <= w2max; b++) for (int a = w1min; a <= w1max; a++) pairs.Add(Tuple.Create(a, b));
        var all = new List<Tuple<double, Cand, int[]>>(); object lk = new object(); int done = 0; var sw = System.Diagnostics.Stopwatch.StartNew();
        Parallel.ForEach(pairs, new ParallelOptions { MaxDegreeOfParallelism = threads }, p =>
        {
            var top = ExhaustK2(ct, n, p.Item1, p.Item2, keep, trueK2);
            var loc = new List<Tuple<double, Cand, int[]>>();
            foreach (var c in top)
            {
                var I = UndoK2(ct, n, c.K2, c.W2); Tuple<double, int[]> best = null;
                for (int r = 0; r < 2; r++) { var s = SolveK1(I, n, c.W1, 1000000, new Random(seed + r * 17 + c.K2[0] + 31 * c.W1 + 7 * c.W2)); if (best == null || s.Item1 > best.Item1) best = s; }
                loc.Add(Tuple.Create(best.Item1, c, best.Item2));
            }
            var lb = loc.OrderByDescending(x => x.Item1).First();
            lock (lk)
            {
                all.AddRange(loc); done++;
                var I = UndoK2(ct, n, lb.Item2.K2, lb.Item2.W2); var P = UndoK1(I, n, lb.Item3, lb.Item2.W1);
                Console.WriteLine("{0,2}/{1,2} best idp {2:F4} q4 {3:F3} {4}  [{5}/{6} {7:F0}s]", lb.Item2.W1, lb.Item2.W2, lb.Item2.Score, lb.Item1, Str(P, 60), done, pairs.Count, sw.Elapsed.TotalSeconds);
            }
        });
        Console.WriteLine("=== overall top 10 by quadgrams");
        foreach (var f in all.OrderByDescending(x => x.Item1).Take(10))
        {
            var I = UndoK2(ct, n, f.Item2.K2, f.Item2.W2); var P = UndoK1(I, n, f.Item3, f.Item2.W1);
            string acc = ""; if (pt != null) { int ok = 0; for (int i = 0; i < n; i++) if (P[i] == pt[i]) ok++; acc = " right " + ok + "/" + n; }
            Console.WriteLine("{0}/{1} idp {2:F4} q4 {3:F3}{4}  {5}\n   key1 {6}\n   key2 {7}", f.Item2.W1, f.Item2.W2, f.Item2.Score, f.Item1, acc, Str(P, 80), string.Join(",", f.Item3), string.Join(",", f.Item2.K2));
        }
    }

    static void Main(string[] a)
    {
        Load(); var sw = System.Diagnostics.Stopwatch.StartNew();
        if (a[0] == "exhaust")
        {   // exhaust CTFILE W1MIN W1MAX W2MIN W2MAX KEEP THREADS SEED
            var ct = ToInts(File.ReadAllText(a[1]));
            RunExhaust(ct, null, int.Parse(a[2]), int.Parse(a[3]), int.Parse(a[4]), int.Parse(a[5]), int.Parse(a[6]), int.Parse(a[7]), int.Parse(a[8]), null);
            Console.WriteLine("elapsed {0:F1}s", sw.Elapsed.TotalSeconds); return;
        }
        if (a[0] == "exhaustplant")
        {   // exhaustplant PLAINFILE OFFSET LEN W1 W2 KEEP THREADS SEED
            var text = ToInts(File.ReadAllText(a[1])); int off = int.Parse(a[2]), len = int.Parse(a[3]), w1 = int.Parse(a[4]), w2 = int.Parse(a[5]);
            int seed = int.Parse(a[8]); var rnd = new Random(seed); var pt = text.Skip(off).Take(len).ToArray();
            var k1 = RandPerm(w1, rnd); var k2 = RandPerm(w2, rnd);
            var ct = EncK2(EncK1(pt, len, k1, w1), len, k2, w2);
            RunExhaust(ct, pt, w1, w1, w2, w2, int.Parse(a[6]), int.Parse(a[7]), seed, k2);
            Console.WriteLine("elapsed {0:F1}s", sw.Elapsed.TotalSeconds); return;
        }
        if (a[0] == "bench")
        {
            int w1 = int.Parse(a[1]), w2 = int.Parse(a[2]); var rnd = new Random(1); int n = 615;
            var ct = new int[n]; for (int i = 0; i < n; i++) ct[i] = rnd.Next(26);
            var g = new Geo(n, w1); int[] map = new int[n], I = new int[n]; var o = RandPerm(w2, rnd); double s = 0;
            for (int it = 0; it < 2000; it++) { ColMap(n, o, w2, map); for (int i = 0; i < n; i++) I[i] = ct[map[i]]; s += IdpScore(I, g); }
            Console.WriteLine("2000 evals w1={0}: {1:F3} ms each", w1, sw.Elapsed.TotalMilliseconds / 2000);
            return;
        }
        if (a[0] == "plant")
        {
            var text = ToInts(File.ReadAllText(a[1])); int off = int.Parse(a[2]), len = int.Parse(a[3]), w1 = int.Parse(a[4]), w2 = int.Parse(a[5]);
            int seed = int.Parse(a[9]); var rnd = new Random(seed); var pt = text.Skip(off).Take(len).ToArray();
            var k1 = RandPerm(w1, rnd); var k2 = RandPerm(w2, rnd);
            var ct = EncK2(EncK1(pt, len, k1, w1), len, k2, w2);
            var trueI = UndoK2(ct, len, k2, w2); var g = new Geo(len, w1);
            Console.WriteLine("true key2 idp {0:F4}; random key2 idp {1:F4}", IdpScore(trueI, g), IdpScore(UndoK2(ct, len, RandPerm(w2, rnd), w2), g));
            Run(ct, pt, w1, w1, w2, w2, int.Parse(a[6]), long.Parse(a[7]), int.Parse(a[8]), seed, k2);
        }
        else
        {
            var ct = ToInts(File.ReadAllText(a[1]));
            Run(ct, null, int.Parse(a[2]), int.Parse(a[3]), int.Parse(a[4]), int.Parse(a[5]), int.Parse(a[6]), long.Parse(a[7]), int.Parse(a[8]), int.Parse(a[9]), null);
        }
        Console.WriteLine("elapsed {0:F1}s", sw.Elapsed.TotalSeconds);
    }
}

