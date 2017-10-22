
#pragma once

#include <conf.h>
#include <env.h>
#include <optarg.h>

namespace suex {

void TurnOnVerboseOutput(const permissions::Permissions &permissions);

void ClearAuthTokens(const permissions::Permissions &permissions);

void ShowVersion();

void ShowPermissions(permissions::Permissions &permissions);

void EditConfiguration(const optargs::OptArgs &opts,
                       const permissions::Permissions &permissions);

void CheckConfiguration(const optargs::OptArgs &opts);

const permissions::Entity *Permit(const permissions::Permissions &permissions,
                                  const optargs::OptArgs &opts);

void SwitchUserAndExecute(const permissions::User &user,
                          char *const *cmdargv,
                          char *const *envp);
}