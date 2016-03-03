/*
 *  Copyright (c) 2008 Brian Tarricone <bjt23@cornell.edu>
 *  Copyright (c) 2008 Stephan Arts <stephan@xfce.org>
 *  Copyright (c) 2008 Jannis Pohlmann <jannis@xfce.org>
 *  Copyright (c) 2008 Mike Massonnet <mmassonnet@xfce.org>
 *  Copyright (c) 2008 Olivier Fourdan <olivier@xfce.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */


#include <config.h>
#include <string.h>

#include <glib.h>
#include <gtk/gtk.h>
#include <dbus/dbus-glib.h>
#include <libwnck/libwnck.h>

#include <libxfce4util/libxfce4util.h>
#include <libxfce4ui/libxfce4ui.h>
#include <xfconf/xfconf.h>
#include "xfwm4-workspace-dialog_ui.h"
#include "xfwm4-workspace-security_ui.h"
#include "monitor-icon.h"

#define WORKSPACES_CHANNEL         "xfwm4"

#define WORKSPACE_NAMES_PROP       "/general/workspace_names"
#define WORKSPACE_COUNT_PROP       "/general/workspace_count"
#define WORKSPACE_SECURE_PROP      "/security/workspace_security_labels"

#define WORKSPACE_NUMBER_QUARK     "workspace_number"

static GdkNativeWindow opt_socket_id = 0;
static gboolean opt_version = FALSE;


enum
{
    COL_NUMBER = 0,
    COL_NAME,
    COL_SANDBOX,
    COL_SETTINGS,
    COL_SANDBOX_ALLOWED,
    N_COLS,
};


static void
workspace_names_update_xfconf(gint workspace,
                              const gchar *new_name)
{
    WnckScreen *screen = wnck_screen_get_default();
    XfconfChannel *channel;
    gchar **names;
    gboolean do_update_xfconf = TRUE;

    channel = xfconf_channel_get(WORKSPACES_CHANNEL);
    names = xfconf_channel_get_string_list(channel, WORKSPACE_NAMES_PROP);

    if(!names) {
        /* the property doesn't exist; let's build one from scratch */
        gint i, n_workspaces = wnck_screen_get_workspace_count(screen);

        names = g_new(gchar *, n_workspaces + 1);
        for(i = 0; i < n_workspaces; ++i) {
            if(G_LIKELY(i != workspace))
                names[i] = g_strdup_printf(_("Workspace %d"), i + 1);
            else
                names[i] = g_strdup(new_name);
        }
        names[n_workspaces] = NULL;
    } else {
        gint i, prop_len = g_strv_length(names);
        gint n_workspaces = wnck_screen_get_workspace_count(screen);

        if(prop_len < n_workspaces) {
            /* the property exists, but it's smaller than the current
             * actual number of workspaces */
            names = g_realloc(names, sizeof(gchar *) * (n_workspaces + 1));
            for(i = prop_len; i < n_workspaces; ++i) {
                if(i != workspace)
                    names[i] = g_strdup_printf(_("Workspace %d"), i + 1);
                else
                    names[i] = g_strdup(new_name);
            }
            names[n_workspaces] = NULL;
        } else {
            /* here we may have a |names| array longer than the actual
             * number of workspaces, but that's fine.  the user might
             * want to re-add a workspace or whatever, and may appreciate
             * that we remember the old name. */
            if(strcmp(names[workspace], new_name)) {
                g_free(names[workspace]);
                names[workspace] = g_strdup(new_name);
            } else {
                /* nothing's actually changed, so don't update the xfconf
                 * property.  this saves us some trouble later. */
                do_update_xfconf = FALSE;
            }
        }
    }

    if(do_update_xfconf)
        xfconf_channel_set_string_list(channel, WORKSPACE_NAMES_PROP, (const gchar **)names);

    g_strfreev(names);
}


static char *
make_security_label(const gboolean val)
{
  if (!val)
    return g_strdup("");
  else
    return g_strdup("untrusted");
}


static void
reset_workspace_security_labels(gint ws_num)
{
    XfconfChannel *channel  = xfconf_channel_get(WORKSPACES_CHANNEL);
    gchar         *property = NULL;

    property = g_strdup_printf("/security/workspace_%d/bandwidth_download", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/bandwidth_upload", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/enable_network", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/enter_replace", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/enter_unsandboxed", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/isolate_dbus", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/let_enter_ws", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/let_escape_ws", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/manual_app_close", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/name", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/net_auto", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/overlay_fs", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/overlay_fs_private_home", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/disable_sound", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/proxy_ip", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/proxy_port", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);

    property = g_strdup_printf("/security/workspace_%d/reopen_files", ws_num);
    xfconf_channel_reset_property(channel, property, TRUE);
    g_free(property);
}


static void
workspace_security_labels_update_xfconf(GtkTreeView *treeview)
{
    XfconfChannel *channel = xfconf_channel_get(WORKSPACES_CHANNEL);
    gchar **names;
    gboolean do_update_xfconf = TRUE;

    GtkTreeModel *model = gtk_tree_view_get_model(treeview);
    GtkTreeIter iter;
    gboolean labeled;
    gint i, n_workspaces = wnck_screen_get_workspace_count(wnck_screen_get_default());
    gint ws_num;

    names = g_new(gchar *, n_workspaces + 1);
    for(i = 0; i < n_workspaces; ++i)
      {
          if (gtk_tree_model_iter_nth_child(model, &iter, NULL, i))
            {
                gtk_tree_model_get(model, &iter, COL_NUMBER, &ws_num, COL_SANDBOX, &labeled, -1);
                names[i] = make_security_label(labeled);
                if (labeled == FALSE)
                  reset_workspace_security_labels(ws_num-1);
            }
      }
    names[n_workspaces] = NULL;

    xfconf_channel_set_string_list(channel, WORKSPACE_SECURE_PROP, (const gchar **)names);

    g_strfreev(names);
}

static void
treeview_ws_names_cell_edited (GtkCellRendererText *cell,
                               const gchar         *path_string,
                               const gchar         *new_name,
                               gpointer             user_data)
{
    GtkTreeView *treeview;
    GtkTreeModel *model;
    GtkTreePath *path;
    GtkTreeIter iter;
    gchar *old_name = NULL;
    gint ws_num = 1;

    treeview = (GtkTreeView *) user_data;
    model = gtk_tree_view_get_model(treeview);
    path = gtk_tree_path_new_from_string (path_string);
    gtk_tree_model_get_iter (model, &iter, path);

    gtk_tree_model_get(model, &iter, COL_NUMBER, &ws_num, COL_NAME, &old_name, -1);
    if(strcmp(old_name, new_name)) {
        gtk_list_store_set(GTK_LIST_STORE(model), &iter, COL_NAME, new_name, -1);
        workspace_names_update_xfconf(ws_num - 1, new_name);
    }

    g_free(old_name);

    gtk_tree_path_free (path);
}

static void
treeview_ws_sandboxed_cell_edited (GtkCellRendererToggle *cell_renderer,
                                   gchar                 *path_string,
                                   gpointer               user_data)
{
    GtkTreeView *treeview;
    GtkTreeModel *model;
    GtkTreePath *path;
    GtkTreeIter iter;
    gboolean old_val = FALSE;
    gint ws_num = 1;

    treeview = (GtkTreeView *) user_data;
    model = gtk_tree_view_get_model(treeview);
    path = gtk_tree_path_new_from_string (path_string);
    if (gtk_tree_model_get_iter (model, &iter, path))
    {
      gtk_tree_model_get(model, &iter, COL_NUMBER, &ws_num, COL_SANDBOX, &old_val, -1);
      gtk_list_store_set(GTK_LIST_STORE(model), &iter, COL_SANDBOX, !old_val, -1);
      gtk_tree_model_row_changed (model, path, &iter);

      workspace_security_labels_update_xfconf(treeview);
    }

    gtk_tree_path_free (path);
}

static void
xfconf_workspace_names_update(GPtrArray *names,
                              gpointer user_data)
{
    GtkTreeView *treeview = GTK_TREE_VIEW(user_data);
    GtkTreeModel *model;
    WnckScreen *screen = wnck_screen_get_default();
    guint i, n_workspaces;
    GtkTreePath *path;
    GtkTreeIter iter;

    g_return_if_fail(GTK_IS_TREE_VIEW(treeview));

    model = gtk_tree_view_get_model(treeview);
    n_workspaces = wnck_screen_get_workspace_count(screen);
    for(i = 0; i < n_workspaces && i < names->len; ++i) {
        GValue *val = g_ptr_array_index(names, i);
        const gchar *new_name;

        if(!G_VALUE_HOLDS_STRING(val)) {
            g_warning("(workspace names) Expected string but got %s for item %d",
                      G_VALUE_TYPE_NAME(val), i);
            continue;
        }

        new_name = g_value_get_string(val);

        path = gtk_tree_path_new_from_indices(i, -1);
        if(gtk_tree_model_get_iter(model, &iter, path)) {
            gchar *old_name = NULL;

            gtk_tree_model_get(model, &iter,
                               COL_NAME, &old_name,
                               -1);
            /* only update the names that have actually changed */
            if(strcmp(old_name, new_name)) {
                gtk_list_store_set(GTK_LIST_STORE(model), &iter,
                                   COL_NAME, new_name,
                                   -1);
            }
            g_free(old_name);
        } else {
            /* must be a new workspace */
            gtk_list_store_append(GTK_LIST_STORE(model), &iter);
            gtk_list_store_set(GTK_LIST_STORE(model), &iter,
                               COL_NUMBER, i + 1,
                               COL_NAME, new_name,
                               -1);
        }

        gtk_tree_path_free(path);
    }

    /* if workspaces got destroyed, we need to remove them from the treeview */
    path = gtk_tree_path_new_from_indices(n_workspaces, -1);
    while(gtk_tree_model_get_iter(model, &iter, path))
        gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
    gtk_tree_path_free(path);
}



static void
xfconf_security_dialog_workspace_names_update(GPtrArray *names,
                                              gpointer user_data)
{
    const gchar *old_name;
    const gchar *new_name;
    guint ws_num;
    GtkEntry *entry = GTK_ENTRY(user_data);

    g_return_if_fail(GTK_IS_ENTRY(entry));

    WnckScreen *screen = wnck_screen_get_default();
    guint i, n_workspaces;

    old_name = gtk_entry_get_text(entry);
    ws_num = GPOINTER_TO_UINT(g_object_get_qdata(G_OBJECT(entry), g_quark_from_static_string(WORKSPACE_NUMBER_QUARK)));
    n_workspaces = wnck_screen_get_workspace_count(screen);

    /* our name is beyond the current number of workspaces... just leave this mess */
    if (ws_num > n_workspaces)
      return;

    for(i = 0; i < n_workspaces && i < names->len; ++i) {
        if (i != ws_num)
            continue;

        GValue *val = g_ptr_array_index(names, i);

        if(!G_VALUE_HOLDS_STRING(val)) {
            g_warning("(workspace names) Expected string but got %s for item %d",
                      G_VALUE_TYPE_NAME(val), i);
            break;
        }

        new_name = g_value_get_string(val);

        if (strcmp(old_name, new_name))
            gtk_entry_set_text(entry, new_name);
    }
}



static void
_xfconf_workspace_names_changed(XfconfChannel *channel,
                                const gchar *property,
                                const GValue *value,
                                gpointer user_data,
                                void (*fun) (GPtrArray *, gpointer))
{
    GPtrArray *names;

    if(G_VALUE_TYPE(value) !=  dbus_g_type_get_collection("GPtrArray",
                                                          G_TYPE_VALUE))
    {
        g_warning("(workspace names) Expected boxed GPtrArray property, got %s",
                  G_VALUE_TYPE_NAME(value));
        return;
    }

    names = g_value_get_boxed(value);
    if(!names)
        return;

    fun(names, user_data);
}



static void
xfconf_workspace_names_changed(XfconfChannel *channel,
                               const gchar *property,
                               const GValue *value,
                               gpointer user_data)
{
    _xfconf_workspace_names_changed(channel, property, value, user_data, xfconf_workspace_names_update);
}



static void
xfconf_security_dialog_workspace_names_changed(XfconfChannel *channel,
                                               const gchar *property,
                                               const GValue *value,
                                               gpointer user_data)
{
    _xfconf_workspace_names_changed(channel, property, value, user_data, xfconf_security_dialog_workspace_names_update);
}



static void
xfconf_workspace_security_labels_update(GPtrArray *names,
                                        GtkTreeView *treeview)
{
    GtkTreeModel *model = gtk_tree_view_get_model(treeview);
    WnckScreen *screen = wnck_screen_get_default();
    guint i, n_workspaces;
    GtkTreePath *path;
    GtkTreeIter iter;

    g_return_if_fail(GTK_IS_TREE_VIEW(treeview));

    n_workspaces = wnck_screen_get_workspace_count(screen);
    for(i = 0; i < n_workspaces && i < names->len; ++i) {
        GValue *val = g_ptr_array_index(names, i);
        const gchar *new_name;

        if(!G_VALUE_HOLDS_STRING(val)) {
            g_warning("(workspace names) Expected string but got %s for item %d",
                      G_VALUE_TYPE_NAME(val), i);
            continue;
        }

        new_name = g_value_get_string(val);

        path = gtk_tree_path_new_from_indices(i, -1);
        if(gtk_tree_model_get_iter(model, &iter, path)) {
            if (strcmp(new_name, "") == 0)
                gtk_list_store_set(GTK_LIST_STORE(model), &iter, COL_SANDBOX, FALSE, COL_SANDBOX_ALLOWED, i!=0, -1);
            else
                gtk_list_store_set(GTK_LIST_STORE(model), &iter, COL_SANDBOX, i!=0, COL_SANDBOX_ALLOWED, i!=0, -1);
            
        } else {
            gtk_list_store_set(GTK_LIST_STORE(model), &iter, COL_SANDBOX, FALSE, COL_SANDBOX_ALLOWED, i!=0, -1);
        }

        gtk_tree_path_free(path);
    }

    /* if workspaces got destroyed, we need to remove them from the treeview */
    path = gtk_tree_path_new_from_indices(n_workspaces, -1);
    while(gtk_tree_model_get_iter(model, &iter, path))
        gtk_list_store_remove(GTK_LIST_STORE(model), &iter);
    gtk_tree_path_free(path);
}



static void
xfconf_workspace_security_labels_changed(XfconfChannel *channel,
                                         const gchar *property,
                                         const GValue *value,
                                         gpointer user_data)
{
    GPtrArray *names;

    if(G_VALUE_TYPE(value) !=  dbus_g_type_get_collection("GPtrArray",
                                                          G_TYPE_VALUE))
    {
        g_warning("(workspace names) Expected boxed GPtrArray property, got %s",
                  G_VALUE_TYPE_NAME(value));
        return;
    }

    names = g_value_get_boxed(value);
    if(!names)
        return;

    xfconf_workspace_security_labels_update(names, user_data);
}



static void
workspace_dialog_count_changed(GtkTreeView *treeview)
{
    GPtrArray *names;
    GPtrArray *labels;
    XfconfChannel *channel;

    channel = xfconf_channel_get(WORKSPACES_CHANNEL);

    names = xfconf_channel_get_arrayv (channel, WORKSPACE_NAMES_PROP);
    if(names != NULL)
    {
        xfconf_workspace_names_update(names, treeview);
        xfconf_array_free(names);
    }

    labels = xfconf_channel_get_arrayv (channel, WORKSPACE_SECURE_PROP);
    if(labels != NULL)
    {
        xfconf_workspace_security_labels_update(labels, treeview);
        xfconf_array_free(labels);
    }
}



static void
workspace_security_dialog_response (GtkWidget *dialog,
                                    gint response_id)
{
  gtk_widget_destroy(dialog);
}


static void
on_let_enter_ws_toggled(GtkToggleButton *button,
                        gpointer user_data)
{
  GtkBuilder *builder = (GtkBuilder *)user_data;
  gboolean active = gtk_toggle_button_get_active(button);

  GtkWidget *widget = GTK_WIDGET (gtk_builder_get_object (builder, "alignment_let_enter_ws"));
  gtk_widget_set_sensitive(widget, active);
}


static void
on_radio_enter_replace_toggled(GtkToggleButton *button,
                               gpointer user_data)
{
  GtkBuilder *builder = (GtkBuilder *)user_data;
  gboolean active = gtk_toggle_button_get_active(button);

  GtkWidget *widget = GTK_WIDGET (gtk_builder_get_object (builder, "alignment_radio_enter_replace"));
  gtk_widget_set_sensitive(widget, active);
}


static void
on_enable_network_toggled(GtkToggleButton *button,
                          gpointer user_data)
{
  GtkBuilder *builder = (GtkBuilder *)user_data;
  gboolean active = gtk_toggle_button_get_active(button);

  GtkWidget *net_auto_check = GTK_WIDGET (gtk_builder_get_object (builder, "net_auto_check"));
  gtk_widget_set_sensitive(net_auto_check, active);

  GtkWidget *isolate_dbus_check = GTK_WIDGET (gtk_builder_get_object (builder, "isolate_dbus_check"));
  gtk_widget_set_sensitive(isolate_dbus_check, active);
}


static void
on_net_auto_check_toggled(GtkToggleButton *button,
                          gpointer user_data)
{
  GtkBuilder *builder = (GtkBuilder *)user_data;
  gboolean active = gtk_toggle_button_get_active(button);

  GtkWidget *widget = GTK_WIDGET (gtk_builder_get_object (builder, "alignment_net_auto_check"));
  gtk_widget_set_sensitive(widget, active);
}


static void
on_overlay_fs_check_toggled(GtkToggleButton *button,
                            gpointer user_data)
{
  GtkBuilder *builder = (GtkBuilder *)user_data;
  gboolean active = gtk_toggle_button_get_active(button);

  GtkWidget *widget = GTK_WIDGET (gtk_builder_get_object (builder, "alignment_overlay_fs_check"));
  gtk_widget_set_sensitive(widget, active);
}


static void
on_security_name_changed(GtkEditable *editable,
                         gpointer     user_data)
{
    GtkEntry *entry = GTK_ENTRY(editable);
    guint ws_num = GPOINTER_TO_UINT(g_object_get_qdata(G_OBJECT(entry), g_quark_from_static_string(WORKSPACE_NUMBER_QUARK)));
    workspace_names_update_xfconf(ws_num, gtk_entry_get_text(entry));
}


static void
___do_nothing(gpointer data)
{
}


static void
workspace_security_configure_widgets (gint           ws_num_display,
                                      gint           ws_num,
                                      const gchar   *ws_name,
                                      GtkBuilder    *builder,
                                      XfconfChannel *channel)
{
    gchar *property = NULL;

    /* Workspace name in Firejail */
    GtkWidget *entry_name = GTK_WIDGET (gtk_builder_get_object (builder, "entry_name"));
    g_object_set_qdata_full(G_OBJECT(entry_name), g_quark_from_static_string(WORKSPACE_NUMBER_QUARK), GUINT_TO_POINTER(ws_num), ___do_nothing);
    if(strlen(gtk_entry_get_text(GTK_ENTRY(entry_name))) == 0)
      gtk_entry_set_text(GTK_ENTRY(entry_name), ws_name);
    g_signal_connect(entry_name, "changed", G_CALLBACK(on_security_name_changed), NULL);
    g_signal_connect(G_OBJECT(channel), "property-changed::" WORKSPACE_NAMES_PROP, G_CALLBACK(xfconf_security_dialog_workspace_names_changed), entry_name);

    /* Enter workspace checkbox */
    GtkWidget *let_enter_ws = GTK_WIDGET (gtk_builder_get_object (builder, "let_enter_ws"));
    property = g_strdup_printf("/security/workspace_%d/let_enter_ws", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)let_enter_ws, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(let_enter_ws)));
    g_free(property);

    g_signal_connect(let_enter_ws, "toggled", G_CALLBACK(on_let_enter_ws_toggled), builder);
    on_let_enter_ws_toggled(GTK_TOGGLE_BUTTON(let_enter_ws), builder);

    /* Escape workspace checkbox */
    GtkWidget *let_escape_ws = GTK_WIDGET (gtk_builder_get_object (builder, "let_escape_ws"));
    property = g_strdup_printf("/security/workspace_%d/let_escape_ws", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)let_escape_ws, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(let_escape_ws)));
    g_free(property);

    /* Radio buttons for behavior on workspace entering */
    GtkWidget *radio_enter_unsandboxed = GTK_WIDGET (gtk_builder_get_object (builder, "radio_enter_unsandboxed"));
    property = g_strdup_printf("/security/workspace_%d/enter_unsandboxed", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)radio_enter_unsandboxed, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(radio_enter_unsandboxed)));
    g_free(property);

    GtkWidget *radio_enter_replace = GTK_WIDGET (gtk_builder_get_object (builder, "radio_enter_replace"));
    property = g_strdup_printf("/security/workspace_%d/enter_replace", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)radio_enter_replace, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(radio_enter_replace)));
    g_free(property);

    g_signal_connect(radio_enter_replace, "toggled", G_CALLBACK(on_radio_enter_replace_toggled), builder);
    on_radio_enter_replace_toggled(GTK_TOGGLE_BUTTON(radio_enter_replace), builder);

    /* File re-opening options */
    GtkWidget *reopen_files_check = GTK_WIDGET (gtk_builder_get_object (builder, "reopen_files_check"));
    property = g_strdup_printf("/security/workspace_%d/reopen_files", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)reopen_files_check, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(reopen_files_check)));
    g_free(property);

    GtkWidget *manual_app_close_check = GTK_WIDGET (gtk_builder_get_object (builder, "manual_app_close_check"));
    property = g_strdup_printf("/security/workspace_%d/manual_app_close", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)manual_app_close_check, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(manual_app_close_check)));
    g_free(property);

    /* Network enabling / namespacing */
    GtkWidget *enable_network_check = GTK_WIDGET (gtk_builder_get_object (builder, "enable_network_check"));
    property = g_strdup_printf("/security/workspace_%d/enable_network", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)enable_network_check, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(enable_network_check)));
    g_free(property);

    g_signal_connect(enable_network_check, "toggled", G_CALLBACK(on_enable_network_toggled), builder);
    on_enable_network_toggled(GTK_TOGGLE_BUTTON(enable_network_check), builder);

    GtkWidget *net_auto_check = GTK_WIDGET (gtk_builder_get_object (builder, "net_auto_check"));
    property = g_strdup_printf("/security/workspace_%d/net_auto", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)net_auto_check, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(net_auto_check)));
    g_free(property);

    GtkWidget *isolate_dbus_check = GTK_WIDGET (gtk_builder_get_object (builder, "isolate_dbus_check"));
    property = g_strdup_printf("/security/workspace_%d/isolate_dbus", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)isolate_dbus_check, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(isolate_dbus_check)));
    g_free(property);

    g_signal_connect(net_auto_check, "toggled", G_CALLBACK(on_net_auto_check_toggled), builder);
    on_net_auto_check_toggled(GTK_TOGGLE_BUTTON(net_auto_check), builder);

    /* Bandwidth settings */
    GtkWidget *spinbutton_dl = GTK_WIDGET (gtk_builder_get_object (builder, "spinbutton_dl"));
    GtkWidget *spinbutton_ul = GTK_WIDGET (gtk_builder_get_object (builder, "spinbutton_ul"));
    gtk_spin_button_set_range (GTK_SPIN_BUTTON (spinbutton_dl), -1, 200000);
    gtk_spin_button_set_range (GTK_SPIN_BUTTON (spinbutton_ul), -1, 200000);
    property = g_strdup_printf("/security/workspace_%d/bandwidth_download", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_INT, (GObject *)spinbutton_dl, "value");
    xfconf_channel_set_int(channel, property, gtk_spin_button_get_value(GTK_SPIN_BUTTON(spinbutton_dl)));
    g_free(property);
    property = g_strdup_printf("/security/workspace_%d/bandwidth_upload", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_INT, (GObject *)spinbutton_ul, "value");
    xfconf_channel_set_int(channel, property, gtk_spin_button_get_value(GTK_SPIN_BUTTON(spinbutton_ul)));
    g_free(property);

    /* Proxy */
    GtkWidget *entry_proxy_ip = GTK_WIDGET (gtk_builder_get_object (builder, "entry_proxy_ip"));
    property = g_strdup_printf("/security/workspace_%d/proxy_ip", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_STRING, (GObject *)entry_proxy_ip, "text");
    xfconf_channel_set_string(channel, property, gtk_entry_get_text(GTK_ENTRY(entry_proxy_ip)));
    g_free(property);

    GtkWidget *entry_proxy_port = GTK_WIDGET (gtk_builder_get_object (builder, "entry_proxy_port"));
    property = g_strdup_printf("/security/workspace_%d/proxy_port", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_STRING, (GObject *)entry_proxy_port, "text");
    xfconf_channel_set_string(channel, property, gtk_entry_get_text(GTK_ENTRY(entry_proxy_port)));
    g_free(property);

    /* Overlay FS options */
    GtkWidget *overlay_fs_check = GTK_WIDGET (gtk_builder_get_object (builder, "overlay_fs_check"));
    property = g_strdup_printf("/security/workspace_%d/overlay_fs", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)overlay_fs_check, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(overlay_fs_check)));
    g_free(property);

    g_signal_connect(overlay_fs_check, "toggled", G_CALLBACK(on_overlay_fs_check_toggled), builder);
    on_overlay_fs_check_toggled(GTK_TOGGLE_BUTTON(overlay_fs_check), builder);

    GtkWidget *overlay_fs_private_home_check = GTK_WIDGET (gtk_builder_get_object (builder, "overlay_fs_private_home_check"));
    property = g_strdup_printf("/security/workspace_%d/overlay_fs_private_home", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)overlay_fs_private_home_check, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(overlay_fs_private_home_check)));
    g_free(property);

    /* Other options */
    GtkWidget *disable_sound_check = GTK_WIDGET (gtk_builder_get_object (builder, "disable_sound_check"));
    property = g_strdup_printf("/security/workspace_%d/disable_sound", ws_num);
    xfconf_g_property_bind(channel, property, G_TYPE_BOOLEAN, (GObject *)disable_sound_check, "active");
    xfconf_channel_set_bool(channel, property, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(disable_sound_check)));
    g_free(property);

    GtkWidget *vbox = GTK_WIDGET (gtk_builder_get_object (builder, "main-vbox"));
    gtk_widget_show_all(vbox);
}


static void
sandbox_settings_dialog_run(gint         ws_num_display,
                            const gchar *ws_name)
{
  GtkBuilder *builder;
  GtkWidget *dialog;
  XfconfChannel *channel;
  gint ws_num = ws_num_display - 1;

  channel = xfconf_channel_get(WORKSPACES_CHANNEL);
  builder = gtk_builder_new();
  gtk_builder_add_from_string(builder, workspace_security_ui, workspace_security_ui_length, NULL);

  if(builder)
    {
      workspace_security_configure_widgets(ws_num_display, ws_num, ws_name, builder, channel);

      dialog = GTK_WIDGET(gtk_builder_get_object(builder, "main-dialog"));
      gtk_widget_show(dialog);
      g_signal_connect(dialog, "response", G_CALLBACK(workspace_security_dialog_response), NULL);
    }
}


static void
cursor_changed(GtkTreeView *treeview,
               gpointer     user_data)
{
  GtkTreeViewColumn *column;
  GtkTreePath       *path;
  GtkTreeModel      *model;
  GtkTreeIter        iter;
  const gchar       *title = NULL;
  gchar             *ws_name = NULL;
  gint               ws_num;
  gboolean           sandboxed;

  gtk_tree_view_get_cursor(treeview, &path, &column);
  if (!path || !column)
    return;

  /* super lame way of getting the settings column */
  title = gtk_tree_view_column_get_title(column);
  if (g_strcmp0(title, "") == 0)
    {
      model = gtk_tree_view_get_model(treeview);
      if (gtk_tree_model_get_iter(model, &iter, path))
        {
          gtk_tree_model_get(model, &iter, COL_NUMBER, &ws_num, COL_NAME, &ws_name, COL_SANDBOX, &sandboxed, -1);
          if (sandboxed)
            sandbox_settings_dialog_run(ws_num, ws_name);
          g_free(ws_name);
        }
    }
}


static void
workspace_dialog_setup_names_treeview(GtkBuilder *builder,
                                      XfconfChannel *channel)
{
    GtkWidget *treeview;
    GtkListStore *ls;
    GtkCellRenderer *render;
    GtkTreeViewColumn *col;
    WnckScreen *screen;
    gchar *longlabel;

    treeview = GTK_WIDGET (gtk_builder_get_object(builder, "treeview_ws_names"));

    ls = gtk_list_store_new(N_COLS, G_TYPE_INT, G_TYPE_STRING, G_TYPE_BOOLEAN, GDK_TYPE_PIXBUF, G_TYPE_BOOLEAN);
    gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), GTK_TREE_MODEL(ls));

    render = gtk_cell_renderer_text_new();
    col = gtk_tree_view_column_new_with_attributes("#", render,
                                                   "text", COL_NUMBER,
                                                   NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), col);

    render = gtk_cell_renderer_text_new();
    g_object_set(G_OBJECT(render),
                 "editable", TRUE,
                 "ellipsize", PANGO_ELLIPSIZE_END,
                 "ellipsize-set", TRUE,
                 NULL);
    longlabel = g_strdup_printf("%s                        ", _("Workspace Name"));
    col = gtk_tree_view_column_new_with_attributes(longlabel,
                                                   render,
                                                   "text", COL_NAME,
                                                   NULL);
    g_free(longlabel);
    g_signal_connect (render, "edited", G_CALLBACK (treeview_ws_names_cell_edited), treeview);

    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), col);

    render = gtk_cell_renderer_toggle_new ();
    gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(treeview), -1, _("Sandboxed"), render, "active", COL_SANDBOX, "sensitive", COL_SANDBOX_ALLOWED, NULL);
    g_signal_connect (render, "toggled", G_CALLBACK (treeview_ws_sandboxed_cell_edited), treeview);


    render = gtk_cell_renderer_pixbuf_new();
    g_object_set(G_OBJECT(render),
                 "follow-state", TRUE,
                 "stock-id", "gtk-preferences",
                 NULL);
    gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(treeview), -1, "", render, "sensitive", COL_SANDBOX, NULL);
    g_signal_connect (treeview, "cursor-changed", G_CALLBACK (cursor_changed), NULL);

    screen = wnck_screen_get_default();
    wnck_screen_force_update (screen);

    workspace_dialog_count_changed (GTK_TREE_VIEW (treeview));

    /* watch ws count changes */
    g_signal_connect_swapped(G_OBJECT(screen), "workspace-created",
                             G_CALLBACK (workspace_dialog_count_changed), treeview);
    g_signal_connect_swapped(G_OBJECT(screen), "workspace-destroyed",
                             G_CALLBACK (workspace_dialog_count_changed), treeview);

    g_signal_connect(G_OBJECT(channel),
                     "property-changed::" WORKSPACE_NAMES_PROP,
                     G_CALLBACK(xfconf_workspace_names_changed), treeview);

    g_signal_connect(G_OBJECT(channel),
                     "property-changed::" WORKSPACE_SECURE_PROP,
                     G_CALLBACK(xfconf_workspace_security_labels_changed), treeview);
                     
    gtk_tree_view_columns_autosize(GTK_TREE_VIEW(treeview));
}

static void
workspace_dialog_configure_widgets (GtkBuilder *builder,
                                    XfconfChannel *channel)
{
    GtkWidget *vbox;

    GdkPixbuf *monitor;
    GtkWidget *image;

    gint wmax, hmax;

    GtkWidget *workspace_count_spinbutton = GTK_WIDGET (gtk_builder_get_object (builder, "workspace_count_spinbutton"));

    GtkWidget *margin_top_spinbutton = GTK_WIDGET (gtk_builder_get_object (builder, "margin_top_spinbutton"));
    GtkWidget *margin_right_spinbutton = GTK_WIDGET (gtk_builder_get_object (builder, "margin_right_spinbutton"));
    GtkWidget *margin_bottom_spinbutton = GTK_WIDGET (gtk_builder_get_object (builder, "margin_bottom_spinbutton"));
    GtkWidget *margin_left_spinbutton = GTK_WIDGET (gtk_builder_get_object (builder, "margin_left_spinbutton"));

    /* Set monitor icon */
    monitor = gdk_pixbuf_new_from_inline (-1, monitor_icon_data, TRUE, NULL);
    image = GTK_WIDGET (gtk_builder_get_object (builder, "monitor_icon"));
    gtk_image_set_from_pixbuf (GTK_IMAGE (image), monitor);
    g_object_unref (monitor);

    /* Set max margins range */
    wmax = gdk_screen_width () / 4;
    hmax = gdk_screen_height () / 4;

    gtk_spin_button_set_range (GTK_SPIN_BUTTON (margin_top_spinbutton), 0, hmax);
    gtk_spin_button_set_range (GTK_SPIN_BUTTON (margin_right_spinbutton), 0, wmax);
    gtk_spin_button_set_range (GTK_SPIN_BUTTON (margin_bottom_spinbutton), 0, hmax);
    gtk_spin_button_set_range (GTK_SPIN_BUTTON (margin_left_spinbutton), 0, wmax);

    /* Bind easy properties */
    xfconf_g_property_bind(channel,
                            "/general/workspace_count",
                            G_TYPE_INT,
                            (GObject *)workspace_count_spinbutton, "value");

    xfconf_g_property_bind(channel,
                            "/general/margin_top",
                            G_TYPE_INT,
                            (GObject *)margin_top_spinbutton, "value");
    xfconf_g_property_bind(channel,
                            "/general/margin_right",
                            G_TYPE_INT,
                            (GObject *)margin_right_spinbutton, "value");
    xfconf_g_property_bind(channel,
                            "/general/margin_bottom",
                            G_TYPE_INT,
                            (GObject *)margin_bottom_spinbutton, "value");
    xfconf_g_property_bind(channel,
                            "/general/margin_left",
                            G_TYPE_INT,
                            (GObject *)margin_left_spinbutton, "value");

    workspace_dialog_setup_names_treeview(builder, channel);

    vbox = GTK_WIDGET (gtk_builder_get_object (builder, "main-vbox"));

    gtk_widget_show_all(vbox);
}


static void
workspace_dialog_response (GtkWidget *dialog,
                           gint response_id)
{
    if (response_id == GTK_RESPONSE_HELP)
    {
        xfce_dialog_show_help (GTK_WINDOW (dialog), "xfwm4",
                               "workspaces", NULL);
    }
    else
    {
        gtk_main_quit ();
    }
}


static GOptionEntry entries[] =
{
    { "socket-id", 's', G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_INT, &opt_socket_id, N_("Settings manager socket"), N_("SOCKET ID") },
    { "version", 'V', G_OPTION_FLAG_IN_MAIN, G_OPTION_ARG_NONE, &opt_version, N_("Version information"), NULL },
    { NULL }
};


int
main(int argc, gchar **argv)
{
    GtkBuilder *builder;
    GtkWidget *dialog;
    GtkWidget *plug;
    GtkWidget *plug_child;
    XfconfChannel *channel;
    GError *cli_error = NULL;

    xfce_textdomain (GETTEXT_PACKAGE, LOCALEDIR, "UTF-8");

    if(!gtk_init_with_args(&argc, &argv, _("."), entries, PACKAGE, &cli_error))
    {
        if (cli_error != NULL)
        {
            g_print (_("%s: %s\nTry %s --help to see a full list of available command line options.\n"), PACKAGE, cli_error->message, PACKAGE_NAME);
            g_error_free (cli_error);
            return 1;
        }
    }

    if(opt_version)
    {
        g_print("%s\n", PACKAGE_STRING);
        return 0;
    }

    if(!xfconf_init (&cli_error)) {
        g_critical ("Failed to contact xfconfd: %s", cli_error->message);
        g_error_free (cli_error);
        return 1;
    }

    channel = xfconf_channel_get(WORKSPACES_CHANNEL);

    if (xfce_titled_dialog_get_type () == 0)
      return 1;

    builder = gtk_builder_new();
    gtk_builder_add_from_string(builder, workspace_dialog_ui, workspace_dialog_ui_length, NULL);

    if(builder) {
        workspace_dialog_configure_widgets (builder, channel);

        if(opt_socket_id == 0) {
            dialog = GTK_WIDGET (gtk_builder_get_object (builder, "main-dialog"));
            gtk_widget_show (dialog);
            g_signal_connect (dialog, "response", G_CALLBACK (workspace_dialog_response), NULL);

            /* To prevent the settings dialog to be saved in the session */
            gdk_set_sm_client_id ("FAKE ID");

            gtk_main ();

            gtk_widget_destroy(dialog);
        } else {
            /* Create plug widget */
            plug = gtk_plug_new (opt_socket_id);
            g_signal_connect (plug, "delete-event", G_CALLBACK (gtk_main_quit), NULL);
            gtk_widget_show (plug);

            /* Get plug child widget */
            plug_child = GTK_WIDGET (gtk_builder_get_object (builder, "plug-child"));
            gtk_widget_reparent (plug_child, plug);
            gtk_widget_show (plug_child);

            /* To prevent the settings dialog to be saved in the session */
            gdk_set_sm_client_id ("FAKE ID");

            /* Stop startup notification */
            gdk_notify_startup_complete ();

            /* Enter main loop */
            gtk_main ();
        }
    }

    xfconf_shutdown();

    return 0;
}
