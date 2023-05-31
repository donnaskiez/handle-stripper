#include "driver.h"

#include "common.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <chrono>
#include <thread>
#include <iostream>

int main()
{
    LPCWSTR name = L"\\\\.\\greeeee";

    DriverInterface driver(name);

    LOG_INFO("Enabling process load callbacks");

    if (!driver.EnableProcessLoadCallbacks())
    {
        LOG_ERROR("Failed to enable process load callbacks");
        return ERROR;
    }

    LOG_INFO("Enabling ObRegisterCallbacks");

    if (!driver.EnableObRegisterCallbacks())
    {
        LOG_ERROR("Failed to enable obregistercallbacks");
        return ERROR;
    }

    LOG_INFO("Waiting for process start event");

    if (!driver.WaitForProcessLoad())
    {
        LOG_ERROR("Failed to wait for process load");
        return ERROR;
    }

    LOG_INFO("Process has started");

    std::this_thread::sleep_for(std::chrono::seconds(5));

    while (true)
    {
        LOG_INFO("Running handle stripper thread");

        if (!driver.RunHandleStripperThread())
        {
            LOG_ERROR("Failed to run handle stripper thread");
            return ERROR;
        }

        std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    int lol;
    std::cin >> lol;

    return 0;
}