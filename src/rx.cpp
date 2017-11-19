#include <rx.h>

bool ::suex::utils::rx::NamedFullMatch(const re2::RE2 &rx,
                                       const std::string &line,
                                       suex::utils::rx::Matches *matches) {
  std::vector<RE2::Arg> args(
      static_cast<uint64_t>(rx.NumberOfCapturingGroups()));
  std::vector<RE2::Arg *> ptrs(
      static_cast<uint64_t>(rx.NumberOfCapturingGroups()));
  std::vector<std::string> results(
      static_cast<uint64_t>(rx.NumberOfCapturingGroups()));

  /// Capture pointers to stack objects and result object in vector..
  for (int i = 0; i < rx.NumberOfCapturingGroups(); ++i) {
    /// Bind argument to string from vector.
    args[i] = &results[i];
    /// Save pointer to argument.
    ptrs[i] = &args[i];
  }

  bool matched =
      re2::RE2::FullMatchN(line, rx, ptrs.data(), rx.NumberOfCapturingGroups());

  for (auto &&kv : rx.NamedCapturingGroups()) {
    matches->emplace(kv.first, results[kv.second - 1]);
  }
  return matched;
}
