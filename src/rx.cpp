#include <rx.h>

bool ::suex::utils::rx::NamedFullMatch(const re2::RE2 &rx,
                                       const std::string &line,
                                       suex::utils::rx::Matches *matches) {
  int ngroups{rx.NumberOfCapturingGroups()};

  RE2::Arg args[ngroups];
  const RE2::Arg *args_p[ngroups];
  std::string groups[ngroups];

  for (int i = 0; i < ngroups; ++i) {
    /// Bind argument to string
    args[i] = &groups[i];
    /// bind argument pointer to arg address
    args_p[i] = &args[i];
  }

  bool matched = re2::RE2::FullMatchN(line, rx, &args_p[0], ngroups);
  if (matched) {
    for (auto &&kv : rx.NamedCapturingGroups()) {
      matches->emplace(kv.first, groups[kv.second - 1]);
    }
  }

  return matched;
}
