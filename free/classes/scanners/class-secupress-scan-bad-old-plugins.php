<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Bad Old Plugins scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Bad_Old_Plugins extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0.1';


	/** Properties. ============================================================================= */

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title = __( 'Check if you are using plugins that have been deleted from the official repository or have not been updated for at least two years.', 'secupress' );
		$this->more  = __( 'Do not use a plugin that has been removed from the official repository, and prevent usage of plugins that have not been maintained for two years at least.', 'secupress' );

		if ( is_network_admin() ) {
			$this->more_fix  = __( 'Select removed and old plugins to be deleted.', 'secupress' );
			$this->more_fix .= '<br/>' . __( 'Not fixable on Multisite.', 'secupress' );
			$this->fixable   = false;
		} elseif ( ! is_multisite() ) {
			$this->more_fix = __( 'Select and delete removed and old plugins.', 'secupress' );
		} else {
			$this->more_fix = __( 'Deactivate removed and old plugins.', 'secupress' );
		}
	}


	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		$messages = array(
			// "good"
			0   => __( 'You don’t use removed or old plugins.', 'secupress' ),
			1   => __( 'You don’t use removed or old plugins anymore.', 'secupress' ),
			2   => __( 'All removed or old plugins have been deleted.', 'secupress' ),
			3   => __( 'All deletable removed or old plugins have been deleted.', 'secupress' ),
			4   => __( 'All removed or old plugins have been deactivated.', 'secupress' ),
			// "warning"
			/** Translators: %s is a file name. */
			100 => __( 'Error, could not read %s.', 'secupress' ),
			101 => __( 'No plugins selected for deletion.', 'secupress' ),
			102 => _n_noop( 'Selected plugin has been deleted (but some are still there).', 'All selected plugins have been deleted (but some are still there).', 'secupress' ),
			103 => _n_noop( 'Sorry, the following plugin could not be deleted: %s.', 'Sorry, the following plugins could not be deleted: %s.', 'secupress' ),
			104 => __( 'No plugins selected for deactivation.', 'secupress' ),
			105 => _n_noop( 'Selected plugin has been deactivated (but some are still there).', 'All selected plugins have been deactivated (but some are still there).', 'secupress' ),
			106 => _n_noop( 'Sorry, the following plugin could not be deactivated: %s.', 'Sorry, the following plugins could not be deactivated: %s.', 'secupress' ),
			/** Translators: %s is the plugin name. */
			107 => sprintf( __( 'You have a big network, %s must work on some data before being able to perform this scan.', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ),
			// "bad"
			/** Translators: 1 is a number, 2 is a plugin name (or a list of plugin names). */
			200 => _n_noop( '<strong>%1$d plugin</strong> is no longer in the WordPress directory: %2$s.', '<strong>%1$d plugins</strong> are no longer in the WordPress directory: %2$s.', 'secupress' ),
			/** Translators: 1 is a number, 2 is a plugin name (or a list of plugin names). */
			201 => _n_noop( '<strong>%1$d plugin</strong> has not been updated for at least 2 years: %2$s.', '<strong>%1$d plugins</strong> have not been updated for at least 2 years: %2$s.', 'secupress' ),
			/** Translators: %s is a plugin name. */
			202 => __( 'You should delete the plugin %s.', 'secupress' ),
			203 => _n_noop( 'Sorry, this plugin could not be deleted.', 'Sorry, those plugins could not be deleted.', 'secupress' ),
			204 => _n_noop( 'The following plugin should be deactivated if you don’t need it: %s.', 'The following plugins should be deactivated if you don’t need them: %s.', 'secupress' ),
			205 => _n_noop( 'Sorry, this plugin could not be deactivated.', 'Sorry, those plugins could not be deactivated.', 'secupress' ),
			// "cantfix"
			/** Translators: %d is a number. */
			300 => _n_noop( '<strong>%d</strong> plugin can be <strong>deleted</strong>.', '<strong>%d</strong> plugins can be <strong>deleted</strong>.', 'secupress' ),
			/** Translators: %d is a number. */
			301 => _n_noop( '<strong>%d</strong> plugin can be <strong>deactivated</strong>.', '<strong>%d</strong> plugins can be <strong>deactivated</strong>.', 'secupress' ),
			302 => __( 'Unable to locate WordPress Plugin directory.', 'secupress' ),
			/** Translators: %s is the plugin name. */
			303 => sprintf( __( 'A new %s menu item has been activated in the relevant site’s administration area to let Administrators know which plugins to deactivate.', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ),
			304 => __( 'No plugins selected.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Getters. ================================================================================ */

	/**
	 * Get the documentation URL.
	 *
	 * @since 1.2.3
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'https://docs.secupress.me/article/117-outdated-and-bad-plugin-check', 'secupress' );
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		if ( ! static::are_centralized_blog_options_filled() ) {
			// "warning"
			$this->add_message( 107 );
			return parent::scan();
		}

		// Multisite, for the current site.
		if ( $this->is_for_current_site() ) {
			// Plugins no longer in directory or not updated in over 2 years.
			$bad_plugins = $this->get_installed_plugins_to_remove();
			$bad_plugins = $bad_plugins['to_deactivate'];

			if ( $count = count( $bad_plugins ) ) {
				// "bad"
				$this->add_message( 204, array( $count, $bad_plugins ) );
			}
		}
		// Network admin or not Multisite.
		else {
			// If we're in a sub-site, don't list the plugins enabled in the network.
			$to_keep = array();

			// Plugins no longer in directory.
			$bad_plugins = $this->get_installed_plugins_no_longer_in_directory();

			if ( $count = count( $bad_plugins ) ) {
				// "bad"
				$this->add_message( 200, array( $count, $count, self::wrap_in_tag( $bad_plugins ) ) );
			}

			// Plugins not updated in over 2 years.
			$bad_plugins = $this->get_installed_plugins_over_2_years();
			$bad_plugins = $to_keep ? array_diff_key( $bad_plugins, $to_keep ) : $bad_plugins;

			if ( $count = count( $bad_plugins ) ) {
				// "bad"
				$this->add_message( 201, array( $count, $count, self::wrap_in_tag( $bad_plugins ) ) );
			}

			// Check for Hello Dolly existence.
			if ( $hello = $this->has_hello_dolly() ) {
				// "bad"
				$this->add_message( 202, $hello );
			}
		}

		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}


	/** Manual fix. ============================================================================= */

	/**
	 * Return an array of actions if a manual fix is needed here.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function need_manual_fix() {
		$bad_plugins = $this->get_installed_plugins_to_remove();
		$actions     = array();

		if ( $bad_plugins['count'] ) {
			if ( $bad_plugins['to_delete'] ) {
				$actions['delete-bad-old-plugins'] = 'delete-bad-old-plugins';
			}
			if ( $bad_plugins['to_deactivate'] ) {
				$actions['deactivate-bad-old-plugins'] = 'deactivate-bad-old-plugins';
			}
		}

		return $actions;
	}


	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		$bad_plugins = $this->get_installed_plugins_to_remove();

		if ( $bad_plugins['count'] ) {
			// DELETE PLUGINS.
			if ( $this->has_fix_action_part( 'delete-bad-old-plugins' ) ) {
				$delete = $this->manual_delete( $bad_plugins['to_delete'], (bool) $bad_plugins['to_deactivate'] );
			}

			// DEACTIVATE PLUGINS.
			if ( $this->has_fix_action_part( 'deactivate-bad-old-plugins' ) ) {
				$deactivate = $this->manual_deactivate( $bad_plugins['to_deactivate'], (bool) $bad_plugins['to_delete'] );
			}

			if ( ! empty( $delete ) && ! empty( $deactivate ) ) {
				// "cantfix": nothing selected in both lists.
				$this->add_fix_message( 304 );
			} elseif ( ! empty( $delete ) ) {
				// "warning": no plugins selected.
				$this->add_fix_message( $delete );
			} elseif ( ! empty( $deactivate ) ) {
				// "warning": no plugins selected.
				$this->add_fix_message( $deactivate );
			}
		} else {
			// "good"
			$this->add_fix_message( 1 );
		}

		return parent::manual_fix();
	}


	/**
	 * Manual fix to delete plugins.
	 *
	 * @since 1.0
	 *
	 * @param (array) $bad_plugins               An array of plugins to delete. Values must be sanitized before.
	 * @param (bool)  $has_plugins_to_deactivate True if some other plugins must be deactivated (it changes the message).
	 */
	protected function manual_delete( $bad_plugins, $has_plugins_to_deactivate ) {
		if ( ! $bad_plugins ) {
			// "good"
			return $this->add_fix_message( 1 );
		}

		// Get the list of plugins to uninstall.
		$selected_plugins = ! empty( $_POST['secupress-fix-delete-bad-old-plugins'] ) && is_array( $_POST['secupress-fix-delete-bad-old-plugins'] ) ? array_filter( $_POST['secupress-fix-delete-bad-old-plugins'] ) : array(); // WPCS: CSRF ok.
		$selected_plugins = $selected_plugins ? array_fill_keys( $selected_plugins, 1 ) : array();
		$selected_plugins = $selected_plugins ? array_intersect_key( $bad_plugins, $selected_plugins ) : array(); // Sanitize submitted values.

		if ( ! $selected_plugins ) {
			if ( $this->has_fix_action_part( 'deactivate-bad-old-plugins' ) ) {
				/*
				 * "warning": no plugins selected.
				 * No `add_fix_message()`, we need to change the status from warning to cantfix if both lists have no selection.
				 */
				return 101;
			}
			// "cantfix": no plugins selected.
			return $this->add_fix_message( 304 );
		}

		// Get filesystem.
		$wp_filesystem = secupress_get_filesystem();
		// Get the base plugin folder.
		$plugins_dir = $wp_filesystem->wp_plugins_dir();

		if ( empty( $plugins_dir ) ) {
			// "cantfix": plugins dir not located.
			return $this->add_fix_message( 302 );
		}

		$plugins_dir = trailingslashit( $plugins_dir );

		$plugin_translations = wp_get_installed_translations( 'plugins' );

		ob_start();

		// Deactivate.
		deactivate_plugins( array_keys( $selected_plugins ) );

		$deleted_plugins = array();

		foreach ( $selected_plugins as $plugin_file => $plugin_data ) {
			// Run Uninstall hook.
			if ( is_uninstallable_plugin( $plugin_file ) ) {
				uninstall_plugin( $plugin_file );
			}

			/** This action is documented in wp-admin/includes/plugin.php */
			do_action( 'delete_plugin', $plugin_file );

			$this_plugin_dir = trailingslashit( dirname( $plugins_dir . $plugin_file ) );

			// If plugin is in its own directory, recursively delete the directory.
			if ( strpos( $plugin_file, '/' ) && $this_plugin_dir !== $plugins_dir ) { // base check on if plugin includes directory separator AND that its not the root plugin folder.
				$deleted = $wp_filesystem->delete( $this_plugin_dir, true );
			} else {
				$deleted = $wp_filesystem->delete( $plugins_dir . $plugin_file );
			}

			/** This action is documented in wp-admin/includes/plugin.php */
			do_action( 'deleted_plugin', $plugin_file, $deleted );

			if ( $deleted ) {
				$deleted_plugins[ $plugin_file ] = 1;

				// Remove language files, silently.
				$plugin_slug = dirname( $plugin_file );

				if ( '.' !== $plugin_slug && ! empty( $plugin_translations[ $plugin_slug ] ) ) {
					$translations = $plugin_translations[ $plugin_slug ];

					foreach ( $translations as $translation => $data ) {
						$wp_filesystem->delete( WP_LANG_DIR . '/plugins/' . $plugin_slug . '-' . $translation . '.po' );
						$wp_filesystem->delete( WP_LANG_DIR . '/plugins/' . $plugin_slug . '-' . $translation . '.mo' );
					}
				}
			}
		}

		ob_end_clean();

		// Everything's deleted, no plugins left.
		if ( ! array_diff_key( $bad_plugins, $deleted_plugins ) ) {
			// "good"
			if ( $has_plugins_to_deactivate ) {
				$this->add_fix_message( 3 );
			} else {
				$this->add_fix_message( 2 );
			}
		}
		// All selected plugins deleted.
		elseif ( ! array_diff_key( $deleted_plugins, $selected_plugins ) ) {
			// "partial": some plugins still need to be deleted.
			$this->add_fix_message( 102, array( count( $selected_plugins ) ) );
		}
		// No plugins deleted.
		elseif ( ! $deleted_plugins ) {
			// "bad"
			$this->add_fix_message( 203, array( count( $bad_plugins ) ) );
		}
		// Some plugins could not be deleted.
		else {
			// "cantfix"
			$not_removed = array_diff_key( $selected_plugins, $deleted_plugins );
			$not_removed = array_map( 'strip_tags', $not_removed );
			$not_removed = array_map( 'esc_html', $not_removed );
			$this->add_fix_message( 103, array( count( $not_removed ), $not_removed ) );
		}

		// Force refresh of plugin update information and cache.
		if ( $deleted_plugins ) {
			if ( $current = get_site_transient( 'update_plugins' ) ) {
				$current->response  = array_diff_key( $current->response, $deleted_plugins );
				$current->no_update = array_diff_key( $current->no_update, $deleted_plugins );
				set_site_transient( 'update_plugins', $current );
			}

			wp_cache_delete( 'plugins', 'plugins' );
		}
	}


	/**
	 * Manual fix to deactivate plugins.
	 *
	 * @since 1.0
	 *
	 * @param (array) $bad_plugins           An array of plugins to deactivate. Values must be sanitized before.
	 * @param (bool)  $has_plugins_to_delete True if some other plugins must be deleted (it changes the message).
	 */
	protected function manual_deactivate( $bad_plugins, $has_plugins_to_delete ) {
		if ( ! $bad_plugins ) {
			if ( $this->is_network_admin() ) {
				// Remove all previously stored messages for sub-sites.
				$this->set_empty_data_for_subsites();
			}
			// "good"
			return $this->add_fix_message( 1 );
		}

		// Get the list of plugins to deactivate.
		$selected_plugins = ! empty( $_POST['secupress-fix-deactivate-bad-old-plugins'] ) && is_array( $_POST['secupress-fix-deactivate-bad-old-plugins'] ) ? array_filter( $_POST['secupress-fix-deactivate-bad-old-plugins'] ) : array(); // WPCS: CSRF ok.
		$selected_plugins = $selected_plugins ? array_fill_keys( $selected_plugins, 1 ) : array();
		$selected_plugins = $selected_plugins ? array_intersect_key( $bad_plugins, $selected_plugins ) : array(); // Sanitize submitted values.

		if ( ! $selected_plugins ) {
			if ( $this->is_network_admin() ) {
				// Remove all previously stored messages for sub-sites.
				$this->set_empty_data_for_subsites();
			}

			if ( $this->has_fix_action_part( 'delete-bad-old-plugins' ) ) {
				/*
				 * "warning": no plugins selected.
				 * No `add_fix_message()`, we need to change the status from warning to cantfix if both lists have no selection.
				 */
				return 104;
			}
			// "cantfix": no plugins selected.
			return $this->add_fix_message( 304 );
		}

		// In the network admin we disable nothing. We only store the selected plugins for later use in the sub-sites scans page.
		if ( $this->is_network_admin() ) {
			$active_subsites_plugins = get_site_option( 'secupress_active_plugins' );

			if ( $active_subsites_plugins && is_array( $active_subsites_plugins ) ) {
				foreach ( $active_subsites_plugins as $site_id => $active_subsite_plugins ) {
					$data = array_intersect_key( $selected_plugins, $active_subsite_plugins );

					if ( $data ) {
						$data = array( count( $data ), $data );
						// Add a scan message for each listed sub-site.
						$this->add_subsite_message( 204, $data, 'scan', $site_id );
					} else {
						$this->set_empty_data_for_subsite( $site_id );
					}
				}
			}
			// "cantfix"
			return $this->add_fix_message( 303 );
		}

		// In a sub-site, deactivate plugins.
		ob_start();
		deactivate_plugins( array_keys( $selected_plugins ) );
		ob_end_clean();

		// Try to see if everything is fine.
		$site_id        = get_current_blog_id();
		$active_plugins = get_site_option( 'secupress_active_plugins' );
		$active_plugins = isset( $active_plugins[ $site_id ] ) ? $active_plugins[ $site_id ] : array();

		// Everything's deactivated, no plugins left.
		if ( ! array_intersect_key( $bad_plugins, $active_plugins ) ) {
			// "good"
			$this->add_fix_message( 4 );
		}
		// All selected plugins deactivated.
		elseif ( ! array_intersect_key( $active_plugins, $selected_plugins ) ) {
			// "partial": some plugins still need to be deactivated.
			$this->add_fix_message( 105, array( count( $selected_plugins ) ) );
		}
		// Some plugins could not be deactivated.
		else {
			$selected_plugins_still_active = array_intersect_key( $active_plugins, $selected_plugins );
			$deactivated_plugins = array_diff_key( $selected_plugins, $selected_plugins_still_active );

			// No plugins deactivated.
			if ( ! $deactivated_plugins ) {
				// "bad"
				$this->add_fix_message( 205, array( count( $bad_plugins ) ) );
			} else {
				// "cantfix"
				$selected_plugins_still_active = array_intersect_key( $bad_plugins, $selected_plugins_still_active );
				$selected_plugins_still_active = array_map( 'strip_tags', $selected_plugins_still_active );
				$selected_plugins_still_active = array_map( 'esc_html', $selected_plugins_still_active );
				$this->add_fix_message( 106, array( count( $selected_plugins_still_active ), $selected_plugins_still_active ) );
			}
		}
	}


	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 1.0
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		$plugins = $this->get_installed_plugins_to_remove();
		$out     = array(
			'delete-bad-old-plugins'     => static::get_messages( 1 ),
			'deactivate-bad-old-plugins' => static::get_messages( 1 ),
		);

		if ( $plugins['to_delete'] ) {
			$form  = '<h4 id="secupress-fix-bad-old-plugins">' . __( 'Checked plugins will be deleted:', 'secupress' ) . '</h4>';
			$form .= '<fieldset aria-labelledby="secupress-fix-bad-old-plugins" class="secupress-boxed-group">';

			foreach ( $plugins['to_delete'] as $plugin_file => $plugin_name ) {
				$is_symlinked = secupress_is_plugin_symlinked( $plugin_file );
				$plugin_name  = esc_html( strip_tags( $plugin_name ) );

				$form .= '<input type="checkbox" id="secupress-fix-delete-bad-old-plugins-' . sanitize_html_class( $plugin_file ) . '" name="secupress-fix-delete-bad-old-plugins[]" value="' . esc_attr( $plugin_file ) . '" ' . ( $is_symlinked ? 'disabled="disabled"' : 'checked="checked"' ) . '/> ';
				$form .= '<label for="secupress-fix-delete-bad-old-plugins-' . sanitize_html_class( $plugin_file ) . '">';
				if ( $is_symlinked ) {
					$form .= '<del>' . $plugin_name . '</del> <span class="description">(' . __( 'symlinked', 'secupress' ) . ')</span>';
				} else {
					$form .= $plugin_name;
				}
				$form .= '</label><br/>';
			}

			$form .= '</fieldset>';
			$out['delete-bad-old-plugins'] = $form;
		}

		if ( $plugins['to_deactivate'] ) {
			if ( $this->is_for_current_site() ) {
				$form  = '<h4 id="secupress-fix-bad-old-plugins-deactiv">' . __( 'Checked plugins will be deactivated:', 'secupress' ) . '</h4>';
			} else {
				$form  = '<h4 id="secupress-fix-bad-old-plugins-deactiv">' . __( 'Checked plugins will be deactivated by Administrators:', 'secupress' ) . '</h4>';
				$form .= '<span class="description">' . _n( 'The following plugin is activated in some of your sites and must be deactivated first. Administrators will be asked to do so.', 'The following plugins are activated in some of your sites and must be deactivated first. Administrators will be asked to do so.', count( $plugins['to_deactivate'] ), 'secupress' ) . '</span>';
			}

			$form .= '<fieldset aria-labelledby="secupress-fix-bad-old-plugins-deactiv" class="secupress-boxed-group">';

			foreach ( $plugins['to_deactivate'] as $plugin_file => $plugin_name ) {
				$is_symlinked = secupress_is_plugin_symlinked( $plugin_file );
				$plugin_name  = esc_html( strip_tags( $plugin_name ) );

				$form .= '<input type="checkbox" id="secupress-fix-deactivate-bad-old-plugins-' . sanitize_html_class( $plugin_file ) . '" name="secupress-fix-deactivate-bad-old-plugins[]" value="' . esc_attr( $plugin_file ) . '" ' . ( $is_symlinked ? 'disabled="disabled"' : 'checked="checked"' ) . '/> ';
				$form .= '<label for="secupress-fix-deactivate-bad-old-plugins-' . sanitize_html_class( $plugin_file ) . '">';
				if ( $is_symlinked ) {
					$form .= '<del>' . $plugin_name . '</del> <span class="description">(' . __( 'symlinked', 'secupress' ) . ')</span>';
				} else {
					$form .= $plugin_name;
				}
				$form .= '</label><br/>';
			}

			$form .= '</fieldset>';
			$out['deactivate-bad-old-plugins'] = $form;
		}

		return $out;
	}


	/** Tools. ================================================================================== */

	/**
	 * Get all plugins to delete.
	 *
	 * @since 1.0
	 *
	 * @return (array).
	 */
	final protected function get_installed_plugins_to_remove() {
		$plugins = array();

		// Plugins no longer in directory.
		$tmp = $this->get_installed_plugins_no_longer_in_directory( true );
		if ( $tmp ) {
			$plugins = $tmp;
		}

		// Plugins not updated in over 2 years.
		$tmp = $this->get_installed_plugins_over_2_years( true );
		if ( $tmp ) {
			$plugins = array_merge( $plugins, $tmp );
		}

		// Byebye Dolly.
		$tmp = $this->has_hello_dolly();
		if ( $tmp ) {
			$plugins = array_merge( $plugins, $tmp );
		}

		return $this->separate_deletable_from_deactivable( $plugins );
	}


	/**
	 * Get plugins no longer in directory.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $for_fix False: for scan. True: for fix.
	 *
	 * @return (array).
	 */
	final protected function get_installed_plugins_no_longer_in_directory( $for_fix = false ) {
		return $this->get_installed_bad_plugins( 'removed_plugins', $for_fix );
	}


	/**
	 * Get plugins not updated in over 2 years.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $for_fix False: for scan. True: for fix.
	 *
	 * @return (array).
	 */
	final protected function get_installed_plugins_over_2_years( $for_fix = false ) {
		return $this->get_installed_bad_plugins( 'notupdated_plugins', $for_fix );
	}


	/**
	 * Get an array of installed "bad" plugins.
	 *
	 * @since 1.0
	 *
	 * @param (string) $plugins_type "removed_plugins" or "notupdated_plugins".
	 * @param (bool)   $for_fix      False: for scan. True: for fix.
	 *
	 * @return (array) An array like `array( path => plugin_name, path => plugin_name )`.
	 */
	final protected function get_installed_bad_plugins( $plugins_type, $for_fix = false ) {
		static $whitelist_error = false;

		if ( 'notupdated_plugins' === $plugins_type ) {
			$bad_plugins  = secupress_get_notupdated_plugins();
			$plugins_file = 'data/not-updated-in-over-two-years-plugin-list.data';
		} else {
			$bad_plugins  = secupress_get_removed_plugins();
			$plugins_file = 'data/no-longer-in-directory-plugin-list.data';
		}

		if ( false === $bad_plugins ) {
			// The file is not readable.
			$plugins_file = SECUPRESS_INC_PATH . $plugins_file;
			$args         = array( '<code>' . str_replace( ABSPATH, '', $plugins_file ) . '</code>' );
			// "warning"
			if ( $for_fix ) {
				$this->add_fix_message( 100, $args );
			} else {
				$this->add_message( 100, $args );
			}
			return false;
		}

		if ( ! $bad_plugins ) {
			return array();
		}

		// Deal with the white list.
		$whitelist = secupress_get_plugins_whitelist();

		if ( false === $whitelist ) {
			// The file is not readable.
			$whitelist = array();

			if ( ! $whitelist_error ) {
				// No need to trigger the error more than once.
				$whitelist_error = true;
				$whitelist_file  = SECUPRESS_INC_PATH . 'data/whitelist-plugin-list.data';
				$args            = array( '<code>' . str_replace( ABSPATH, '', $whitelist_file ) . '</code>' );
				// "warning"
				if ( $for_fix ) {
					$this->add_fix_message( 100, $args );
				} else {
					$this->add_message( 100, $args );
				}
			}
		}

		$bad_plugins = array_diff_key( $bad_plugins, $whitelist );

		if ( ! $bad_plugins ) {
			return array();
		}

		$all_plugins = get_plugins();
		$bad_plugins = array_flip( $bad_plugins );
		$bad_plugins = array_intersect_key( $all_plugins, $bad_plugins );
		$bad_plugins = wp_list_pluck( $bad_plugins, 'Name' );

		return $bad_plugins;
	}


	/**
	 * Dolly are you here?
	 *
	 * @since 1.0
	 *
	 * @return (array) An array like `array( path => plugin_name )`.
	 */
	final protected function has_hello_dolly() {
		$plugins = array();

		// Sub-sites don't need to delete Dolly.
		if ( ! $this->is_for_current_site() && file_exists( WP_PLUGIN_DIR . '/hello.php' ) ) {
			$plugins['hello.php'] = '<code>Hello Dolly</code>';
		}

		return $plugins;
	}


	/**
	 * From a list of plugins, separate them in 2: those that can be deleted and those that can be deactivated first (from a sub-site).
	 *
	 * @since 1.0
	 *
	 * @param (array) $plugins An array of "bad" plugins.
	 *
	 * @return (array) An array like `array( path => plugin_name )`.
	 */
	final protected function separate_deletable_from_deactivable( $plugins ) {
		if ( ! $plugins ) {
			return array(
				'to_delete'     => array(),
				'to_deactivate' => array(),
				'count'         => 0,
			);
		}

		// Network: plugins activated in sub-sites must be deactivated in each sub-site first.
		if ( $this->is_network_admin() ) {
			$active_subsites_plugins_tmp = get_site_option( 'secupress_active_plugins' );
			$active_subsites_plugins     = array();

			if ( $active_subsites_plugins_tmp && is_array( $active_subsites_plugins_tmp ) ) {
				foreach ( $active_subsites_plugins_tmp as $site_id => $active_subsite_plugins ) {
					$active_subsites_plugins = array_merge( $active_subsites_plugins, $active_subsite_plugins );
				}
			}

			// Let's act like Hello Dolly is not enabled in any sub-site, so we won't need Administrators aproval and we'll be able to delete it directly.
			unset( $active_subsites_plugins_tmp, $active_subsites_plugins['hello.php'] );
			$active_subsites_plugins = array_diff_key( $active_subsites_plugins, get_site_option( 'active_sitewide_plugins' ) );

			$out = array(
				// Plugins that are network activated or not activated in any site can be deleted.
				'to_delete'     => array_diff_key( $plugins, $active_subsites_plugins ),
				// Plugins activated in subsites.
				'to_deactivate' => array_intersect_key( $plugins, $active_subsites_plugins ),
			);
		}
		// Sub-site: limit to plugins activated in this sub-site.
		elseif ( $this->is_for_current_site() ) {
			$site_id         = get_current_blog_id();
			$subsite_plugins = get_site_option( 'secupress_active_plugins' );
			$subsite_plugins = ! empty( $subsite_plugins[ $site_id ] ) ? $subsite_plugins[ $site_id ] : array();

			$out = array(
				// In a sub-site we don't delete any plugin.
				'to_delete'     => array(),
				// We only deactivate them.
				'to_deactivate' => array_intersect_key( $plugins, $subsite_plugins ),
			);
		}
		// Not a multisite.
		else {
			$out = array(
				// All plugins can be deleted.
				'to_delete'     => $plugins,
				// No need to deactivate anything.
				'to_deactivate' => array(),
			);
		}

		$out['count'] = count( $out['to_delete'] ) + count( $out['to_deactivate'] );
		return $out;
	}
}
