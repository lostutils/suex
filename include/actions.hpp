
#pragma once

#include <conf.hpp>
#include <env.hpp>
#include <optarg.hpp>

namespace suex {

void TurnOnVerboseOutput();

void ClearAuthTokens(const permissions::Permissions &permissions);

void ShowVersion();

void ShowPermissions(const permissions::Permissions &permissions);

void EditConfiguration(const optargs::OptArgs &opts,
                       const permissions::Permissions &permissions);

void CheckConfiguration(const optargs::OptArgs &opts);

const permissions::Entity *Permit(const permissions::Permissions &permissions,
                                  const optargs::OptArgs &opts);

void SwitchUserAndExecute(const permissions::User &user,
                          const std::vector<char *> &cmdargv,
                          char *const envp[]);
}  // namespace suex
