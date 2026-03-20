"""GUI for managing AD Group Audit settings.

Single ADUC-style hierarchical tree showing OUs and Groups with a
Protected column. Toggling Protected on an OU cascades to all child
OUs and groups beneath it. Groups can be toggled individually.
Protected groups are audited and reported on.
Launched via --manage CLI flag.
"""

import logging
import tkinter as tk
from tkinter import ttk, messagebox

from ad_group_audit.ad_service import ADService
from ad_group_audit.db_service import DatabaseService
from ad_group_audit.models import AppConfig

logger = logging.getLogger("ad_group_audit")

# Prefix to distinguish group iids from OU iids in the treeview
_GRP_PREFIX = "GRP::"


def _build_ou_hierarchy(ous, groups):
    """Build a tree from flat OU list with groups as leaves.

    Returns (root_children, node_map).
    """
    node_map = {}
    for ou in ous:
        node_map[ou["ou_dn"]] = {
            "dn": ou["ou_dn"],
            "name": ou["ou_name"],
            "is_protected": ou["is_protected"],
            "children": [],
            "groups": [],
            "kind": "ou",
        }

    for grp in groups:
        parent_dn = _find_parent_ou(grp["dn"], node_map)
        entry = {
            "dn": grp["dn"],
            "name": grp["name"],
            "is_protected": grp["is_protected"],
            "kind": "group",
        }
        if parent_dn:
            node_map[parent_dn]["groups"].append(entry)

    root_children = []
    for ou in ous:
        dn = ou["ou_dn"]
        parts = dn.split(",", 1)
        parent_dn = parts[1].strip() if len(parts) == 2 else None
        if parent_dn and parent_dn in node_map:
            node_map[parent_dn]["children"].append(node_map[dn])
        else:
            root_children.append(node_map[dn])

    def sort_tree(nodes):
        nodes.sort(key=lambda n: n["name"].lower())
        for n in nodes:
            n["groups"].sort(key=lambda g: g["name"].lower())
            sort_tree(n["children"])

    sort_tree(root_children)
    return root_children, node_map


def _find_parent_ou(dn, ou_map):
    """Walk up the DN to find the first parent that is a known OU."""
    parts = dn.split(",")
    for i in range(1, len(parts)):
        candidate = ",".join(parts[i:])
        if candidate in ou_map:
            return candidate
    return None


class AuditManagerGUI:
    """ADUC-style GUI for managing group protection."""

    CHECK = "[X]"
    UNCHECK = "[ ]"

    def __init__(self, config: AppConfig, db: DatabaseService):
        self.config = config
        self.db = db
        self.ou_changes = {}     # {ou_dn: bool}  -- is_protected
        self.group_changes = {}  # {group_dn: bool}  -- is_protected
        self.node_map = {}
        self.all_ous = []
        self.all_groups = []

        self.root = tk.Tk()
        self.root.title("AD Group Audit - Protected Groups")
        self.root.geometry("750x600")
        self.root.minsize(600, 400)

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=5)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Domain:").pack(side=tk.LEFT)
        self.domain_var = tk.StringVar()
        domain_names = [d.name for d in self.config.domains]
        self.domain_combo = ttk.Combobox(
            top, textvariable=self.domain_var,
            values=domain_names, state="readonly", width=30,
        )
        self.domain_combo.pack(side=tk.LEFT, padx=(5, 15))
        if domain_names:
            self.domain_combo.current(0)
        self.domain_combo.bind("<<ComboboxSelected>>", lambda e: self._sync_and_load())

        ttk.Label(top, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._refresh_tree())
        ttk.Entry(top, textvariable=self.search_var, width=25).pack(side=tk.LEFT, padx=5)

        ttk.Button(top, text="Sync from AD", command=self._sync_and_load).pack(side=tk.RIGHT)

        # Tree with single Protected column
        tree_frame = ttk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tree = ttk.Treeview(
            tree_frame, columns=("protected",), selectmode="browse",
        )
        self.tree.heading("#0", text="Name", anchor=tk.W)
        self.tree.heading("protected", text="Protected", anchor=tk.CENTER)
        self.tree.column("#0", width=550, stretch=True)
        self.tree.column("protected", width=80, stretch=False, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self._on_double_click)

        bottom = ttk.Frame(self.root, padding=5)
        bottom.pack(fill=tk.X)
        ttk.Button(bottom, text="Save Changes", command=self._save_changes).pack(side=tk.RIGHT)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.status_var).pack(side=tk.LEFT)

        self._sync_and_load()

    def _sync_and_load(self):
        """Sync OUs from AD into DB, then reload tree."""
        domain_name = self.domain_var.get()
        if not domain_name:
            return

        domain_config = None
        for d in self.config.domains:
            if d.name == domain_name:
                domain_config = d
                break
        if not domain_config:
            return

        self.status_var.set("Syncing OUs from AD...")
        self.root.update_idletasks()

        try:
            ad = ADService(
                domain_config,
                username=domain_config.ldap_username,
                password=domain_config.ldap_password,
            )
            ad.connect()
            all_ad_ous = ad.get_all_ous()
            ad.disconnect()

            for ou in all_ad_ous:
                self.db.upsert_ou(ou["dn"], ou["name"], domain_name)

            self.status_var.set(f"Synced {len(all_ad_ous)} OUs from AD")
        except Exception as e:
            self.status_var.set(f"AD sync failed: {e}")
            logger.error("AD sync failed: %s", e)

        self._load_data()

    def _load_data(self):
        """Load OUs and groups from DB and refresh tree."""
        domain_name = self.domain_var.get()
        if not domain_name:
            return
        self.all_ous = self.db.get_all_ous(domain_name)
        self.all_groups = self.db.get_all_groups_for_domain(domain_name)
        self.ou_changes.clear()
        self.group_changes.clear()
        self._refresh_tree()

    def _get_expanded_ids(self, parent=""):
        """Collect IIDs of all currently expanded (open) nodes."""
        expanded = set()
        for iid in self.tree.get_children(parent):
            if self.tree.item(iid, "open"):
                expanded.add(iid)
            expanded |= self._get_expanded_ids(iid)
        return expanded

    def _refresh_tree(self):
        """Rebuild the treeview, preserving expand state."""
        expanded_ids = self._get_expanded_ids()
        self.tree.delete(*self.tree.get_children())
        root_children, self.node_map = _build_ou_hierarchy(
            self.all_ous, self.all_groups
        )

        search = self.search_var.get().strip().lower()
        if search:
            matching = set()
            for ou in self.all_ous:
                if search in ou["ou_name"].lower() or search in ou["ou_dn"].lower():
                    dn = ou["ou_dn"]
                    matching.add(dn)
                    parts = dn.split(",")
                    for i in range(1, len(parts)):
                        matching.add(",".join(parts[i:]))
            for grp in self.all_groups:
                if search in grp["name"].lower() or search in grp["dn"].lower():
                    matching.add(_GRP_PREFIX + grp["dn"])
                    parts = grp["dn"].split(",")
                    for i in range(1, len(parts)):
                        matching.add(",".join(parts[i:]))
            self._insert_nodes("", root_children, matching, expanded_ids)
        else:
            self._insert_nodes("", root_children, None, expanded_ids)

        self._update_pending_count()

    def _insert_nodes(self, parent_iid, nodes, filter_dns, expanded_ids):
        """Recursively insert OU nodes and their group children."""
        for node in nodes:
            dn = node["dn"]
            if filter_dns is not None and dn not in filter_dns:
                continue

            protected = self._get_ou_flag(dn, node["is_protected"])
            is_open = bool(filter_dns) or (dn in expanded_ids)

            iid = self.tree.insert(
                parent_iid, tk.END, iid=dn, text=node["name"],
                values=(self.CHECK if protected else self.UNCHECK,),
                open=is_open,
            )

            # Groups as leaves
            for grp in node["groups"]:
                grp_iid = _GRP_PREFIX + grp["dn"]
                if filter_dns is not None and grp_iid not in filter_dns:
                    continue
                grp_prot = self._get_group_flag(grp["dn"], grp["is_protected"])
                self.tree.insert(
                    iid, tk.END, iid=grp_iid, text=grp["name"],
                    values=(self.CHECK if grp_prot else self.UNCHECK,),
                )

            self._insert_nodes(iid, node["children"], filter_dns, expanded_ids)

    def _get_ou_flag(self, ou_dn, default):
        """Get effective OU protected flag: pending or saved."""
        if ou_dn in self.ou_changes:
            return self.ou_changes[ou_dn]
        return default

    def _get_group_flag(self, group_dn, default):
        """Get effective group protected flag: pending or saved."""
        if group_dn in self.group_changes:
            return self.group_changes[group_dn]
        return default

    def _on_double_click(self, event):
        """Toggle Protected on the clicked item."""
        region = self.tree.identify_region(event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)
        item = self.tree.identify_row(event.y)
        if not item or col != "#1":
            return

        if item.startswith(_GRP_PREFIX):
            group_dn = item[len(_GRP_PREFIX):]
            current = self._get_group_flag(
                group_dn, self._db_group_flag(group_dn)
            )
            self.group_changes[group_dn] = not current
        else:
            current = self._get_ou_flag(item, self._db_ou_flag(item))
            new_val = not current
            self.ou_changes[item] = new_val
            self._cascade(item, new_val)

        self._refresh_tree()

    def _db_ou_flag(self, ou_dn):
        for ou in self.all_ous:
            if ou["ou_dn"] == ou_dn:
                return ou["is_protected"]
        return False

    def _db_group_flag(self, group_dn):
        for grp in self.all_groups:
            if grp["dn"] == group_dn:
                return grp["is_protected"]
        return False

    def _cascade(self, ou_dn, value):
        """Cascade protected flag to all child OUs and groups."""
        node = self.node_map.get(ou_dn)
        if not node:
            return
        for grp in node["groups"]:
            self.group_changes[grp["dn"]] = value
        for child in node["children"]:
            self.ou_changes[child["dn"]] = value
            self._cascade(child["dn"], value)

    def _update_pending_count(self):
        count = len(self.ou_changes) + len(self.group_changes)
        if count:
            self.status_var.set(f"{count} item(s) with pending changes")
        else:
            self.status_var.set("Ready")

    def _save_changes(self):
        """Persist all pending changes to DB."""
        if not self.ou_changes and not self.group_changes:
            messagebox.showinfo("Save", "No changes to save.")
            return

        saved = 0
        for ou_dn, protected in self.ou_changes.items():
            self.db.set_ou_protected(ou_dn, protected)
            saved += 1
        for group_dn, protected in self.group_changes.items():
            self.db.set_group_protected(group_dn, protected)
            saved += 1

        self.ou_changes.clear()
        self.group_changes.clear()
        self._load_data()
        messagebox.showinfo("Save", f"Saved changes for {saved} item(s).")

    def run(self):
        """Start the GUI main loop."""
        self.root.mainloop()
