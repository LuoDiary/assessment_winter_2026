#include <gtest/gtest.h>

#include "rm_a0/a0_01_temperature.hpp"
#include "rm_a0/a0_02_leap_year.hpp"
#include "rm_a0/a0_03_range_sum.hpp"
#include "rm_a0/a0_04_vowel_count.hpp"
#include "rm_a0/a0_05_score_stats.hpp"
#include "rm_a0/a0_06_bigint.hpp"
#include "rm_a0/a0_07_log_analyzer.hpp"
#include "rm_a0/a0_08_raii_handle.hpp"
#include "rm_a0/a0_lib.hpp"

#include <cstdio>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

#include <windows.h>
#include <string>

static std::string MakeTempPath() {
    char temp_path[MAX_PATH];
    DWORD size = GetTempPathA(MAX_PATH, temp_path);
    if (size == 0 || size >= MAX_PATH) {
        return {}; // 获取临时目录失败
    }

    char temp_file[MAX_PATH];
    UINT result = GetTempFileNameA(temp_path, "rm_a0", 0, temp_file);
    if (result == 0) {
        return {}; // 创建临时文件名失败
    }

    return std::string(temp_file);
}
TEST(A001Temperature, ConvertsAndFormats) {
    bool ok = false;
    EXPECT_EQ(rm_a0::SolveTemperature("0\n", ok), "32.00\n");
    ASSERT_TRUE(ok);
    EXPECT_EQ(rm_a0::SolveTemperature("100", ok), "212.00\n");
    ASSERT_TRUE(ok);
    EXPECT_EQ(rm_a0::SolveTemperature("-40", ok), "-40.00\n");
    ASSERT_TRUE(ok);
}

TEST(A001Temperature, InvalidInput) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveTemperature("abc", ok), "");
    EXPECT_FALSE(ok);
}

TEST(A002LeapYear, HandlesCommonRules) {
    bool ok = false;
    EXPECT_EQ(rm_a0::SolveLeapYear("2000\n", ok), "YES\n");
    ASSERT_TRUE(ok);
    EXPECT_EQ(rm_a0::SolveLeapYear("1900", ok), "NO\n");
    ASSERT_TRUE(ok);
    EXPECT_EQ(rm_a0::SolveLeapYear("2004", ok), "YES\n");
    ASSERT_TRUE(ok);
    EXPECT_EQ(rm_a0::SolveLeapYear("2001", ok), "NO\n");
    ASSERT_TRUE(ok);
}

TEST(A002LeapYear, InvalidInput) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveLeapYear("nope", ok), "");
    EXPECT_FALSE(ok);
}

TEST(A003RangeSum, ComputesArithmeticSum) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveRangeSum("1 3\n", ok), "6\n");
    EXPECT_TRUE(ok);

    ok = true;
    EXPECT_EQ(rm_a0::SolveRangeSum("-2 1145141919810\n", ok), "3936897706503538848\n");
    EXPECT_TRUE(ok);
}

TEST(A003RangeSum, InvalidInput) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveRangeSum("hello\n", ok), "");
    EXPECT_FALSE(ok);
}

TEST(A004VowelCount, CountsVowelsCaseInsensitive) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveVowelCount("hello\n", ok), "2\n");
    EXPECT_TRUE(ok);

    ok = true;
    EXPECT_EQ(rm_a0::SolveVowelCount("AEIOU xyz\n", ok), "5\n");
    EXPECT_TRUE(ok);
}

TEST(A004VowelCount, EmptyLineIsZero) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveVowelCount("\n", ok), "0\n");
    EXPECT_TRUE(ok);
}

TEST(A005ScoreStats, ComputesTopAndAverage) {
    const std::string input =
        "3\n"
        "alice 10\n"
        "bob 20\n"
        "cara 0\n";
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveScoreStats(input, ok), "top=bob 20\navg=10.00\n");
    EXPECT_TRUE(ok);
}

TEST(A005ScoreStats, InvalidInput) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveScoreStats("\n", ok), "");
    EXPECT_FALSE(ok);

    ok = true;
    EXPECT_EQ(rm_a0::SolveScoreStats("0\n", ok), "");
    EXPECT_FALSE(ok);
}

TEST(A006BigInt, AddsLargeNumbers) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveBigIntAdd("999\n1\n", ok), "1000\n");
    EXPECT_TRUE(ok);

    ok = true;
    EXPECT_EQ(rm_a0::SolveBigIntAdd("123456789012345678901234567890\n987654321098765432109876543210\n", ok), "1111111110111111111011111111100\n");
    EXPECT_TRUE(ok);
}

TEST(A006BigInt, HandlesLeadingZeros) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveBigIntAdd("000\n0000\n", ok), "0\n");
    EXPECT_TRUE(ok);
}

TEST(A007LogAnalyzer, SummarizesLogFile) {
    const std::string path = MakeTempPath();
    ASSERT_FALSE(path.empty());

    {
        std::ofstream out(path);
        ASSERT_TRUE(out.is_open());
        out << "INFO 10\n";
        out << "WARN 20\n";
        out << "ERROR 30\n";
        out << "INFO 40\n";
    }

    bool ok = true;
    EXPECT_EQ(rm_a0::SolveLogAnalyzer(path + "\n", ok), "INFO=2\nWARN=1\nERROR=1\navg=25.00\nmax=INFO 40\n");
    EXPECT_TRUE(ok);

    std::remove(path.c_str());
}

TEST(A007LogAnalyzer, MissingFileFails) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveLogAnalyzer("/definitely/not/a/file\n", ok), "FAIL\n");
    EXPECT_FALSE(ok);
}

TEST(A008RaiiHandle, CopiesFileContent) {
    const std::string in_path  = MakeTempPath();
    const std::string out_path = MakeTempPath();
    ASSERT_FALSE(in_path.empty());
    ASSERT_FALSE(out_path.empty());

    {
        std::ofstream out(in_path, std::ios::binary);
        ASSERT_TRUE(out.is_open());
        out << "hello world\n";
    }

    bool ok = true;
    EXPECT_EQ(rm_a0::SolveRaiiCopy(in_path + " " + out_path + "\n", ok), "OK\n");
    EXPECT_TRUE(ok);

    {
        std::ifstream in(out_path, std::ios::binary);
        ASSERT_TRUE(in.is_open());
        std::string s;
        std::getline(in, s);
        EXPECT_EQ(s, "hello world");
    }

    std::remove(in_path.c_str());
    std::remove(out_path.c_str());
}

TEST(A008RaiiHandle, MissingInputFileFails) {
    bool ok = true;
    EXPECT_EQ(rm_a0::SolveRaiiCopy("/definitely/not/a/file out.bin\n", ok), "FAIL\n");
    EXPECT_FALSE(ok);
}


TEST(A009TextPipeline, TrimUpperReplace) {
    bool ok  = false;
    auto out = rm_a0::RunTextPipeline("trim|upper|replace:RM:ROBO", { "  rm 2026  ", "hello rm", "" }, ok);
    ASSERT_TRUE(ok);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], "ROBO 2026");
    EXPECT_EQ(out[1], "HELLO ROBO");
    EXPECT_EQ(out[2], "");
}

TEST(A009TextPipeline, UnknownTransform) {
    bool ok = false;
    (void)rm_a0::RunTextPipeline("unknown", { "a" }, ok);
    EXPECT_FALSE(ok);
}

TEST(A010RuleEngine, LevelAndMsRules) {
    bool ok                          = false;
    long long total                  = 0;
    std::vector<std::string> rules   = { "level>=WARN", "ms>50" };
    std::vector<rm_a0::Event> events = {
        { "INFO", 10, "ok" },
        { "WARN", 60, "motor overcurrent" },
        { "ERROR", 49, "imu timeout" },
    };

    auto hit = rm_a0::RunRuleEngine(rules, events, total, ok);
    ASSERT_TRUE(ok);
    ASSERT_EQ(hit.size(), 2u);
    EXPECT_EQ(hit[0], 2);
    EXPECT_EQ(hit[1], 1);
    EXPECT_EQ(total, 2);
}

TEST(A010RuleEngine, InvalidRule) {
    bool ok         = false;
    long long total = 0;
    (void)rm_a0::RunRuleEngine({ "nope" }, { { "INFO", 1, "a" } }, total, ok);
    EXPECT_FALSE(ok);
}

TEST(A011CommandDispatcher, GrepCommand) {
    bool ok         = false;
    std::string out = rm_a0::RunCommandDispatcher("grep rm\nhello\nrm2026\nabc\n", ok);
    ASSERT_TRUE(ok);
    EXPECT_EQ(out, "2:rm2026\n");
}

TEST(A011CommandDispatcher, UnknownCommand) {
    bool ok         = false;
    std::string out = rm_a0::RunCommandDispatcher("unknown\nx\n", ok);
    EXPECT_FALSE(ok);
    EXPECT_EQ(out, "FAIL\n");
}


