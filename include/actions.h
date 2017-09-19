
#pragma once

#include <env.h>
#include <optarg.h>
#include <conf.h>

namespace doas {

void TurnOnVerboseOutput(const permissions::Permissions &permissions);

void ClearAuthTokens(const permissions::Permissions &permissions);

void ShowVersion();

void ShowPermissions(permissions::Permissions &permissions);

void EditConfiguration(const optargs::OptArgs &opts,
                       const permissions::Permissions &permissions);

void CheckConfiguration(const optargs::OptArgs &opts);

const permissions::Entity *Permit(const permissions::Permissions &permissions,
                                  const optargs::OptArgs &opts);

void DoAs(const permissions::User &user, char *const cmdargv[], char *const envp[]);
}