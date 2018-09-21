#pragma once

#ifdef INFLAME_EXPORTS
#define INFLAME_API __declspec(dllexport)
#else
#define INFLAME_API __declspec(dllimport)
#endif

extern "C" INFLAME_API void manualMap(char* dllName, int PID);
