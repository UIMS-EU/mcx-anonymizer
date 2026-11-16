// SPDX-License-Identifier: GPL-3.0-or-later
#include "cli/commands.hpp"
#include "cli/passphrase.hpp"
#include "mcxanon/reveal.hpp"

#include <cstdio>
#include <memory>

namespace mcxanon::cli {

Result<DataDirResolution> resolve_data_dir_for(const GlobalOptions& g) {
  DataDirOptions o = data_dir_options_from_environment();
  if (!g.data_dir.empty()) o.explicit_dir = g.data_dir;
  return resolve_data_dir(o);
}

Result<Project> open_project(const GlobalOptions& g, const std::string& name) {
  auto where = resolve_data_dir_for(g);
  if (!where) return std::unexpected(where.error());
  auto enc = Project::is_encrypted(*where, name);
  if (!enc) return std::unexpected(enc.error());
  if (!*enc) return Project::open(*where, name, g.wait);
  auto pw = get_passphrase(passphrase_inputs_from_environment(g.passphrase_file), false);
  if (!pw) return std::unexpected(pw.error());
  auto p = Project::open(*where, name, g.wait, *pw);
  std::fill(pw->begin(), pw->end(), '\0');
  return p;
}

void register_project_commands(CLI::App& app, const GlobalOptions& g,
                               std::vector<std::pair<CLI::App*, Command>>& commands) {
  CLI::App* project = app.add_subcommand("project", "manage projects (secret and mapping)");
  project->require_subcommand(1);

  struct InitArgs {
    std::string name;
    bool encrypt = false;
  };
  auto init_args = std::make_shared<InitArgs>();
  CLI::App* init = project->add_subcommand("init", "create a new project");
  init->add_option("name", init_args->name, "project name ([A-Za-z0-9._-], 1-64 characters)")->required();
  init->add_flag("--encrypt", init_args->encrypt, "encrypt the secret and the mapping with a passphrase");
  commands.emplace_back(init, [&g, init_args]() -> Result<void> {
    auto where = resolve_data_dir_for(g);
    if (!where) return std::unexpected(where.error());
    std::optional<std::string> pw;
    if (init_args->encrypt) {
      auto p = get_passphrase(passphrase_inputs_from_environment(g.passphrase_file), true);
      if (!p) return std::unexpected(p.error());
      pw = std::move(*p);
    }
    auto p = pw ? Project::create(*where, init_args->name, std::string_view(*pw))
                : Project::create(*where, init_args->name);
    if (pw) std::fill(pw->begin(), pw->end(), '\0');
    if (!p) return std::unexpected(p.error());
    std::printf("%s\n", p->directory().c_str());
    return {};
  });

  CLI::App* list = project->add_subcommand("list", "list the projects (no mapping contents)");
  commands.emplace_back(list, [&g]() -> Result<void> {
    auto where = resolve_data_dir_for(g);
    if (!where) return std::unexpected(where.error());
    auto ps = Project::list(*where);
    if (!ps) return std::unexpected(ps.error());
    for (const auto& p : *ps) {
      if (p.entries) {
        std::printf("%s\t%s\t%zu entries\n", p.name.c_str(), p.encrypted ? "encrypted" : "plain", *p.entries);
      } else {
        std::printf("%s\t%s\n", p.name.c_str(), p.encrypted ? "encrypted" : "plain");
      }
    }
    return {};
  });

  struct MapArgs {
    std::string name;
    std::string category;
  };
  auto map_args = std::make_shared<MapArgs>();
  CLI::App* show = project->add_subcommand("show-map", "print the mapping (local inspection only)");
  show->add_option("name", map_args->name, "project name")->required();
  show->add_option("--category", map_args->category,
                   "only this category (e.g. ipv4, mac, sip-user, domain, tel, call-id)");
  commands.emplace_back(show, [&g, map_args]() -> Result<void> {
    if (!map_args->category.empty() && !is_mapping_category(map_args->category)) {
      return fail(ErrorCode::usage, "unknown mapping category '" + map_args->category + "'");
    }
    auto p = open_project(g, map_args->name);
    if (!p) return std::unexpected(p.error());
    std::fputs("mcxanon: the following lines contain ORIGINAL values; do not share them\n", stderr);
    std::puts("category\toriginal\tpseudonym\tcounter\truns_seen");
    for (const auto& r : p->mapping_rows()) {
      if (!map_args->category.empty() && r.category != map_args->category) continue;
      std::printf("%s\t%s\t%s\t%u\t%u\n", r.category.c_str(), r.original.c_str(), r.pseudonym.c_str(), r.counter,
                  r.runs_seen);
    }
    return {};
  });

  struct LookupArgs {
    std::string name, value;
    bool original = false;
  };
  auto look_args = std::make_shared<LookupArgs>();
  CLI::App* look = project->add_subcommand("lookup", "look up one value: a pseudonym, or with --original an original");
  look->add_option("name", look_args->name, "project name")->required();
  look->add_option("value", look_args->value, "the value to look up")->required();
  look->add_flag("--original", look_args->original, "the value is an original already seen; print its pseudonym");
  commands.emplace_back(look, [&g, look_args]() -> Result<void> {
    std::fputs(kRevealBanner, stderr);
    auto p = open_project(g, look_args->name);
    if (!p) return std::unexpected(p.error());
    std::string unresolved;
    auto r = lookup(*p, look_args->value,
                    look_args->original ? LookupDirection::to_pseudonym : LookupDirection::to_original, &unresolved);
    if (!r) return std::unexpected(r.error());
    if (r->empty()) {
      if (look_args->original && !unresolved.empty()) {
        return fail(ErrorCode::leak, "'" + unresolved + "' has not been seen by project '" + look_args->name + "'");
      }
      return fail(ErrorCode::leak, "not found in project '" + look_args->name + "'");
    }
    for (const auto& l : *r) {
      std::printf("%s\t%s\t%s\n", l.category.c_str(), l.query.c_str(), l.counterpart.c_str());
    }
    return {};
  });

  auto where_name = std::make_shared<std::string>();
  CLI::App* where = project->add_subcommand("where", "print the data directory or a project's directory");
  where->add_option("name", *where_name, "project name");
  commands.emplace_back(where, [&g, where_name]() -> Result<void> {
    auto w = resolve_data_dir_for(g);
    if (!w) return std::unexpected(w.error());
    if (where_name->empty()) {
      std::printf("%s\t(%s)\n", w->path.c_str(), std::string(to_string(w->source)).c_str());
    } else {
      if (!is_valid_project_name(*where_name)) return fail(ErrorCode::usage, "invalid project name");
      std::printf("%s\n", (w->path / "projects" / *where_name).c_str());
    }
    return {};
  });
}

}  // namespace mcxanon::cli
