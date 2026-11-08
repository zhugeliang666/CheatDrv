#pragma once

#include <string>

#include <unordered_map>

#include <windows.h>

enum class Language
{

    Chinese,

    English
};

struct TranslationPair
{

    std::string chinese;

    std::string english;
};

class LanguageManager
{

  private:
    Language currentLanguage;

    std::unordered_map<std::string, TranslationPair> translations;

    LanguageManager();

    Language DetectLanguage();

    void InitializeTranslations();

  public:
    static LanguageManager &GetInstance();

    std::string GetString(const std::string &key);

    const char *GetChar(const std::string &key);

    Language GetCurrentLanguage() const;

    void SetLanguage(Language lang);
};

#define L10N(key) LanguageManager::GetInstance().GetString(key)

#define L10NC(key) LanguageManager::GetInstance().GetChar(key)