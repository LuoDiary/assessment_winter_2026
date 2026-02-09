#include "rm_a0/a0_lib.hpp"

#include "rm_a0/a0_01_temperature.hpp"
#include "rm_a0/a0_02_leap_year.hpp"
#include "rm_a0/a0_03_range_sum.hpp"
#include "rm_a0/a0_04_vowel_count.hpp"
#include "rm_a0/a0_05_score_stats.hpp"
#include "rm_a0/a0_06_bigint.hpp"
#include "rm_a0/a0_07_log_analyzer.hpp"
#include "rm_a0/a0_08_raii_handle.hpp"

#include <cctype>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>

namespace rm_a0 {

// ==================== A0-01 Temperature ====================
// TODO: 完成下面函数的实现
double CelsiusToFahrenheit(double celsius) {
    return celsius * 9 / 5 + 32;
}
// 这里是格式化输出的函数
std::string FormatFahrenheit(double fahrenheit) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(2) << fahrenheit << std::endl;
    return out.str();
}

std::string SolveTemperature(const std::string& input, bool& ok) {
    std::istringstream in(input);
    double celsius = 0.0;
    if (!(in >> celsius)) {
        ok = false;
        return {};
    }

    ok = true;
    return FormatFahrenheit(CelsiusToFahrenheit(celsius));
}

// ==================== A0-02 Leap Year ====================
// TODO: 完成下面函数的实现
bool IsLeapYear(int year) {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}
// TODO: 完成下面函数的实现,不要新增行数，只修改返回值
std::string FormatLeapYearAnswer(bool is_leap_year) {
    return is_leap_year ? "YES\n" : "NO\n";
}

std::string SolveLeapYear(const std::string& input, bool& ok) {
    std::istringstream in(input);
    int year = 0;
    if (!(in >> year)) {
        ok = false;
        return {};
    }

    ok = true;
    return FormatLeapYearAnswer(IsLeapYear(year));
}

// ==================== A0-03 Range Sum ====================
// TODO: 完成下面函数的实现
long long RangeSum(long long l, long long r) {
    return (l + r) * (r - l + 1) / 2;
}

std::string SolveRangeSum(const std::string& input, bool& ok) {
    std::istringstream in(input);
    long long l = 0;
    long long r = 0;
    if (!(in >> l >> r)) {
        ok = false;
        return {};
    }
    ok = true;
    std::ostringstream out;
    out << RangeSum(l, r) << "\n";
    return out.str();
}

// ==================== A0-04 Vowel Count ====================

namespace {
    namespace a0_04_detail {

        bool IsVowelChar(unsigned char c) {
            if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
            return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u';
        }

    } // namespace a0_04_detail
} // namespace

std::size_t CountVowels(const std::string& line) {
    std::size_t count = 0;
    // TODO: 完成下面函数的实现
    for (unsigned char c : line)
        if (a0_04_detail::IsVowelChar(c))
            count++;
    return count;
}

std::string SolveVowelCount(const std::string& input, bool& ok) {
    std::istringstream in(input);
    std::string line;
    if (!std::getline(in, line)) {
        ok = false;
        return {};
    }
    ok = true;
    std::ostringstream out;
    out << CountVowels(line) << "\n";
    return out.str();
}

// ==================== A0-05 Score Stats ====================

ScoreStatsResult ComputeScoreStats(const std::string& input, bool& ok) {
    ok = false;
    std::istringstream in(input);
    // TODO: 完成下面函数的实现
    ScoreStatsResult res, solve;
    int n;
    in >> n;
    if (n == 0) return res;
    for (int i = 0; i < n; i++)
    {
        in >> solve.top_name >> solve.top_score;
        res.avg += solve.top_score;
        if (solve.top_score > res.top_score)
            res.top_name = solve.top_name, res.top_score = solve.top_score;
    }
    res.avg /= n;
    ok = true;
    return res;
}

std::string SolveScoreStats(const std::string& input, bool& ok) {
    auto res = ComputeScoreStats(input, ok);
    if (!ok) {
        return {};
    }

    std::ostringstream out;
    out << "top=" << res.top_name << " " << res.top_score << "\n";
    out << "avg=" << std::fixed << std::setprecision(2) << res.avg << "\n";
    return out.str();
}

// ==================== A0-06 BigInt ====================

// TODO: 参考hpp完成类实现
/*
at a0_06_bigint.hpp:
class BigInt {
public:
  BigInt();

  // Constructs from a non-negative decimal string.
  explicit BigInt(const std::string &s);

  friend BigInt operator+(const BigInt &a, const BigInt &b);
  friend std::ostream &operator<<(std::ostream &os, const BigInt &x);

private:
  // Little-endian digits, each 0..9.
  std::vector<int> digits_;
};
*/

BigInt::BigInt() : digits_() {}

BigInt::BigInt(const std::string& s)
{
    for (auto it = s.rbegin(); it != s.rend(); ++it)
        digits_.push_back(*it - '0');
}

BigInt operator+(const BigInt& a, const BigInt& b)
{
    BigInt res;
    int carry = 0;
    int i = 0;
    while (i < a.digits_.size() || i < b.digits_.size())
    {
        if (i < a.digits_.size())
            carry += a.digits_[i];
        if (i < b.digits_.size())
            carry += b.digits_[i];
        res.digits_.push_back(carry % 10);
        carry = carry / 10;
        i++;
    }
    if (carry)
        res.digits_.push_back(carry);
    return res;
}

std::ostream& operator<<(std::ostream& os, const BigInt& x)
{
    bool flag = false;
    for (int i = x.digits_.size() - 1; i >= 0; i--)
        if (flag || x.digits_[i] || !i)
            os << x.digits_[i], flag = true;
    return os;
}

std::string SolveBigIntAdd(const std::string& input, bool& ok) {
    std::istringstream in(input);
    std::string a;
    std::string b;
    std::ostringstream out;
    if (!std::getline(in, a)) {
        ok = false;
        return {};
    }
    if (!std::getline(in, b)) {
        ok = false;
        return {};
    }

    BigInt x(a), y(b);
    out << x + y << "\n";

    ok = true;
    return out.str();
}

// ==================== A0-07 Log Analyzer ====================
/*
at a0_07_log_analyzer.hpp:
struct LogStats {
  long long info = 0;
  long long warn = 0;
  long long error = 0;
  double avg_ms = 0.0;
  std::string max_level;
  long long max_ms = 0;
};
*/
LogStats AnalyzeLogFile(const std::string& path, bool& ok) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return {};
    }
    LogStats log;
    std::string line;
    long long cnt = 0;
    while (std::getline(file, line))
    {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string level;
        long long ms;
        iss >> level >> ms;
        if (level == "INFO")
            log.info++;
        else if (level == "WARN")
            log.warn++;
        else if (level == "ERROR")
            log.error++;
        if (ms > log.max_ms)
            log.max_level = level,log.max_ms = ms;
        log.avg_ms += ms;
        cnt++;
    }
    if (cnt) log.avg_ms /= cnt;
    ok = true;
    return log;
}

std::string SolveLogAnalyzer(const std::string& input, bool& ok) {
    std::istringstream in(input);
    std::string path;
    if (!std::getline(in, path)) {
        ok = false;
        return {};
    }
    if (path.empty()) {
        ok = false;
        return "FAIL\n";
    }

    bool file_ok = false;
    LogStats s   = AnalyzeLogFile(path, file_ok);
    if (!file_ok) {
        ok = false;
        return "FAIL\n";
    }

    ok = true;
    std::ostringstream out;
    out << "INFO=" << s.info << "\n";
    out << "WARN=" << s.warn << "\n";
    out << "ERROR=" << s.error << "\n";
    out << "avg=" << std::fixed << std::setprecision(2) << s.avg_ms << "\n";
    out << "max=" << s.max_level << " " << s.max_ms << "\n";
    return out.str();
}

// ==================== A0-08 RAII Handle ====================

// TODO: 参考hpp完成类实现
/*
at a0_08_raii_handle.hpp:
class FileHandle {
public:
  FileHandle() = default;
  FileHandle(const char *path, const char *mode);
  ~FileHandle();

  FileHandle(const FileHandle &) = delete;
  FileHandle &operator=(const FileHandle &) = delete;

  FileHandle(FileHandle &&other) noexcept;
  FileHandle &operator=(FileHandle &&other) noexcept;

  bool valid() const;
  FILE *get() const;

private:
  FILE *fp_ = nullptr;
};
*/

FileHandle::FileHandle(const char* path, const char* mode) : fp_(fopen(path, mode)) {}
FileHandle::~FileHandle() { if (fp_) fclose(fp_); }
bool FileHandle::valid() const { return fp_ != nullptr; }
FILE* FileHandle::get() const { return fp_; }

bool CopyFile(const std::string& in_path, const std::string& out_path) {
    FileHandle in(in_path.c_str(), "rb");
    FileHandle out(out_path.c_str(), "wb");
    if (!in.valid() || !out.valid())
        return false;
    // copy file
    char buf;
    while (fread(&buf, 1, 1, in.get()) == 1)
        fwrite(&buf, 1, 1, out.get());
    return true;
}

std::string SolveRaiiCopy(const std::string& input, bool& ok) {
    std::istringstream in(input);
    std::string in_path;
    std::string out_path;
    if (!(in >> in_path >> out_path)) {
        ok = false;
        return {};
    }

    if (CopyFile(in_path, out_path)) {
        ok = true;
        return "OK\n";
    }

    ok = false;
    return "FAIL\n";
}

// ==================== A0-09 Text Pipeline====================

std::vector<std::string> RunTextPipeline(const std::string& pipeline, const std::vector<std::string>& lines, bool& ok) {
    if (pipeline.empty() || lines.empty())
        return {};
    std::vector<std::string> res, tokens;
    std::istringstream ss(pipeline);
    std::string token;
    while (std::getline(ss, token, '|'))
        tokens.push_back(token);
    for (std::string line : lines)
    {
        // if (line.empty()) continue;
        for (const auto& token : tokens)
        {
            if (token == "trim")
            {
                size_t start = line.find_first_not_of(" \t\n\r\f\v");
                size_t end = line.find_last_not_of(" \t\n\r\f\v");
                if( start != std::string::npos && end != std::string::npos)
                    line = line.substr(start, end - start + 1);
            }
            else if (token == "upper")
                std::transform(line.begin(), line.end(), line.begin(), [](unsigned char c) {return std::toupper(c);});
            else if (token.substr(0, 7) == "replace")
            {
                size_t pos1 = token.find_first_of(":");
                size_t pos2 = token.find_last_of(":");
                if (pos1 == std::string::npos || pos2 == std::string::npos)
                    return {};
                std::string from = token.substr(pos1 + 1, pos2 - pos1 - 1);
                std::string to = token.substr(pos2 + 1);
                size_t pos = 0;
                while((pos=line.find(from, pos))!=std::string::npos)
                {
                    line.replace(pos, from.length(), to);
                    pos += to.length();
                }
            }
            else
                return {};
        }
        res.push_back(line);
    }
    ok = true;
    return res;
}

// ==================== A0-10 Rule Engine ====================

class IRule
{
protected:
    mutable int ruleCnt = 0;
    bool autoCnt(bool cmp) const
    {
        if (cmp) ruleCnt++;
        return cmp;
    }
public:
    virtual ~IRule() = default;
    virtual bool match(const Event& event) const = 0;
    int getRuleCnt() const { return ruleCnt; }
};

class RuleLevel : public IRule
{
private:
    std::unordered_map<std::string, int> level_map;
    int setLevel;
    int findMap(const std::string& level) const
    {
        auto findResult = level_map.find(level);
        if (findResult == level_map.end())
            return -1;
        return findResult->second;
    }
public:
    RuleLevel(const std::string& level)
    {
        level_map["INFO"] = 1;
        level_map["WARN"] = 2;
        level_map["ERROR"] = 3;
        setLevel = findMap(level);
    }
    bool match(const Event& event) const override
    {
        int findResult = findMap(event.level);
        if (findResult == -1)
            return false;
        return autoCnt(findResult >= setLevel);
    }
};

class RuleTime : public IRule
{
private:
    int setTime;
public:
    RuleTime(const std::string& time) :setTime(std::stoi(time)) {}
    bool match(const Event& event) const override
    {
        return autoCnt(event.ms > setTime);
    }
};

class RuleMsg : public IRule
{
private:
    std::string setMsg;
public:
    RuleMsg(const std::string& msg) :setMsg(msg) {}
    bool match(const Event& event) const override
    {
        return autoCnt(event.msg.find(setMsg) != std::string::npos);
    }
};

class RuleEngine
{
private:
    std::vector<std::unique_ptr<IRule>> rules;
public:
    RuleEngine() = default;
    ~RuleEngine() = default;
    bool addRule(const std::string& rule)
    {
        if (rule.substr(0, 7) == "level>=")
            rules.push_back(std::make_unique<RuleLevel>(rule.substr(7)));
        else if (rule.substr(0, 3) == "ms>")
            rules.push_back(std::make_unique<RuleTime>(rule.substr(3)));
        else if (rule.substr(0, 13) == "msg_contains:")
            rules.push_back(std::make_unique<RuleMsg>(rule.substr(13)));
        else
            return false;
        return true;
    }
    void run(const Event& event)
    {
        for (const auto& rule : rules)
        {
            rule->match(event);
        }
    }
    std::vector<long long> getRuleCnt(long long& total_cnt) const
    {
        std::vector<long long> res;
        for (const auto& rule : rules)
        {
            total_cnt += rule->getRuleCnt() == 0 ? 0 : 1;
            res.push_back(rule->getRuleCnt());
        }
        return res;
    }
};

std::vector<long long> RunRuleEngine(
    const std::vector<std::string>& rule_specs,
    const std::vector<Event>& events,
    long long& total_any,
    bool& ok
) {
    RuleEngine engine;
    for (const auto& rule : rule_specs)
        if (!engine.addRule(rule))
            return {};
    for (const auto& event : events)
        engine.run(event);
    ok = true;
    return engine.getRuleCnt(total_any);
}

// ==================== A0-11 Command Dispatcher====================

std::string RunCommandDispatcher(const std::string& full_stdin, bool& ok) {
    (void)full_stdin;
    ok = false;
    return "FAIL\n";
}

} // namespace rm_a0
