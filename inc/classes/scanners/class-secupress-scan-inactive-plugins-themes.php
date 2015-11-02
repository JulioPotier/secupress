<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Inactive Plugins Themes scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Inactive_Plugins_Themes extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if you have some deactivated plugins or themes.', 'secupress' );
		self::$more  = __( 'Even deactivated plugins or themes can potentially be exploited to some vulnerabilities.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You don\'t have any deactivated plugins or themes.', 'secupress' ),
			1   => __( 'All inactive plugins have been deleted.', 'secupress' ),
			2   => __( 'All inactive themes have been deleted.', 'secupress' ),
			// wraning
			100 => __( 'No plugins selected.', 'secupress' ),
			101 => __( 'All selected plugins have been deleted (but some are still there).', 'secupress' ),
			102 => _n_noop( 'Sorry, the following plugin could not be deleted: %s.', 'Sorry, the following plugins could not be deleted: %s.', 'secupress' ),
			103 => __( 'No themes selected.', 'secupress' ),
			104 => __( 'All selected themes have been deleted (but some are still there).', 'secupress' ),
			105 => _n_noop( 'Sorry, the following theme could not be deleted: %s.', 'Sorry, the following themes could not be deleted: %s.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%d deactivated plugin</strong>, if you don\'t need it, delete it: %s', '<strong>%d deactivated plugins</strong>, if you don\'t need them, delete them: %s', 'secupress' ),
			201 => _n_noop( '<strong>%d deactivated theme</strong>, if you don\'t need it, delete it: %s', '<strong>%d deactivated themes</strong>, if you don\'t need them, delete them: %s', 'secupress' ),
			202 => _n_noop( 'Sorry, this plugin could not be deleted.', 'Sorry, those plugins could not be deleted.', 'secupress' ),
			203 => _n_noop( 'Sorry, this theme could not be deleted.', 'Sorry, those themes could not be deleted.', 'secupress' ),
			// cantfix
			300 => _n_noop( '%d plugin is deactivated.', '%d plugins are deactivated.', 'secupress' ),
			301 => _n_noop( '%d theme is deactivated.', '%d themes are deactivated.', 'secupress' ),
			302 => __( 'Unable to locate WordPress Plugin directory.' ), // WPi18n
			303 => __( 'Unable to locate WordPress theme directory.' ), // WPi18n
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		$lists = static::get_inactive_plugins_and_themes();

		// Inactive plugins
		if ( $count = count( $lists['plugins'] ) ) {
			// bad
			$lists['plugins'] = wp_list_pluck( $lists['plugins'], 'Name' );
			$lists['plugins'] = self::wrap_in_tag( $lists['plugins'], 'strong' );
			$this->add_message( 200, array( $count, $count, $lists['plugins'] ) );
		}

		// Inactive themes
		if ( $count = count( $lists['themes'] ) ) {
			// bad
			$lists['themes'] = wp_list_pluck( $lists['themes'], 'Name' );
			$lists['themes'] = self::wrap_in_tag( $lists['themes'], 'strong' );
			$this->add_message( 201, array( $count, $count, $lists['themes'] ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		$lists = static::get_inactive_plugins_and_themes();

		// Inactive plugins
		if ( $count = count( $lists['plugins'] ) ) {
			$this->add_fix_message( 300, array( $count, $count ) );
			$this->add_fix_action( 'delete-inactive-plugins' );
		}

		// Inactive themes
		if ( $count = count( $lists['themes'] ) ) {
			$this->add_fix_message( 301, array( $count, $count ) );
			$this->add_fix_action( 'delete-inactive-themes' );
		}

		// good
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	public function manual_fix() {
		$wp_filesystem = static::get_filesystem();
		$inactive      = static::get_inactive_plugins_and_themes();

		ob_start();

		// PLUGINS
		if ( $this->has_fix_action_part( 'delete-inactive-plugins' ) ) {

			// Get the list of plugins to uninstall.
			$selected_plugins = ! empty( $_POST['secupress-fix-delete-inactive-plugins'] ) && is_array( $_POST['secupress-fix-delete-inactive-plugins'] ) ? array_filter( array_map( 'esc_attr', $_POST['secupress-fix-delete-inactive-plugins'] ) ) : array();
			$selected_plugins = $selected_plugins ? array_fill_keys( $selected_plugins, 1 ) : array();
			$selected_plugins = $selected_plugins ? array_intersect_key( $inactive['plugins'], $selected_plugins ) : array();

			if ( $selected_plugins ) {
				//Get the base plugin folder
				$plugins_dir = $wp_filesystem->wp_plugins_dir();

				if ( ! empty( $plugins_dir ) ) {
					$plugins_dir     = trailingslashit( $plugins_dir );
					$deleted_plugins = array();
					$count_inactive  = count( $inactive['plugins'] );
					$count_selected  = count( $selected_plugins );

					foreach ( $selected_plugins as $plugin_file => $plugin_data ) {
						// Run Uninstall hook
						if ( is_uninstallable_plugin( $plugin_file ) ) {
							uninstall_plugin( $plugin_file );
						}

						$this_plugin_dir = trailingslashit( dirname( $plugins_dir . $plugin_file ) );

						// If plugin is in its own directory, recursively delete the directory.
						if ( strpos( $plugin_file, '/' ) && $this_plugin_dir !== $plugins_dir ) { // base check on if plugin includes directory separator AND that its not the root plugin folder.
							$deleted = $wp_filesystem->delete( $this_plugin_dir, true );
						}
						else {
							$deleted = $wp_filesystem->delete( $plugins_dir . $plugin_file );
						}

						if ( $deleted ) {
							$deleted_plugins[ $plugin_file ] = 1;
						}
					}

					$count_deleted = count( $deleted_plugins );

					// Everything's deleted, no plugins left.
					if ( $count_deleted === $count_inactive ) {
						// good
						$this->add_fix_message( 1 );
					}
					// All selected plugins deleted.
					elseif ( $count_deleted === $count_selected ) {
						// "partial": some plugins still need to be deleted.
						$this->add_fix_message( 101 );
					}
					// No plugins deleted.
					elseif ( ! $count_deleted ) {
						// bad
						$this->add_fix_message( 202, array( $count_inactive ) );
					}
					// Some plugins could not be deleted.
					else {
						// cantfix
						$not_removed = array_diff_key( $selected_plugins, $deleted_plugins );
						$not_removed = wp_list_pluck( $not_removed, 'Name' );
						$this->add_fix_message( 102, array( count( $not_removed ), $not_removed ) );
					}

					// Force refresh of plugin update information.
					if ( $count_deleted && $current = get_site_transient( 'update_plugins' ) ) {
						$current->response = array_diff_key( $current->response, $deleted_plugins );
						set_site_transient( 'update_plugins', $current );
					}

				} else {
					// cantfix: plugins dir not located.
					$this->add_fix_message( 302 );
				}

			} else {
				// warning: no plugins selected.
				$this->add_fix_message( 100 );
			}
		}

		// THEMES
		if ( $this->has_fix_action_part( 'delete-inactive-themes' ) ) {

			$selected_themes = ! empty( $_POST['secupress-fix-delete-inactive-themes'] ) && is_array( $_POST['secupress-fix-delete-inactive-themes'] ) ? array_filter( array_map( 'esc_attr', $_POST['secupress-fix-delete-inactive-themes'] ) ) : array();
			$selected_themes = $selected_themes ? array_fill_keys( $selected_themes, 1 ) : array();
			$selected_themes = $selected_themes ? array_intersect_key( $inactive['themes'], $selected_themes ) : array();

			if ( $selected_themes ) {
				//Get the base theme folder
				$themes_dir = $wp_filesystem->wp_themes_dir();

				if ( ! empty( $themes_dir ) ) {
					$themes_dir      = trailingslashit( $themes_dir );
					$deleted_themes  = array();
					$count_inactive  = count( $inactive['themes'] );
					$count_selected  = count( $selected_themes );

					foreach ( $selected_themes as $theme_file => $theme_data ) {
						$this_theme_dir  = trailingslashit( $themes_dir . $theme_file );

						if ( $wp_filesystem->delete( $this_theme_dir, true ) ) {
							$deleted_themes[ $theme_file ] = 1;
						}
					}

					$count_deleted = count( $deleted_themes );

					// Everything's deleted, no themes left.
					if ( $count_deleted === $count_inactive ) {
						// good
						$this->add_fix_message( 2 );
					}
					// All selected themes deleted.
					elseif ( $count_deleted === $count_selected ) {
						// "partial": some themes still need to be deleted.
						$this->add_fix_message( 104 );
					}
					// No themes deleted.
					elseif ( ! $count_deleted ) {
						// bad
						$this->add_fix_message( 203, array( $count_inactive ) );
					}
					// Some themes could not be deleted.
					else {
						// cantfix
						$not_removed = array_diff_key( $selected_themes, $deleted_themes );
						$not_removed = wp_list_pluck( $not_removed, 'Name' );
						$this->add_fix_message( 105, array( count( $not_removed ), $not_removed ) );
					}

					// Force refresh of theme update information
					delete_site_transient( 'update_themes' );

				} else {
					// cantfix: themes dir not located.
					$this->add_fix_message( 303 );
				}

			} else {
				// warning: no themes selected.
				$this->add_fix_message( 103 );
			}
		}

		ob_end_clean();

		return parent::manual_fix();
	}


	protected function get_fix_action_template_parts() {
		$forms = array();
		$lists = static::get_inactive_plugins_and_themes();

		if ( $lists['plugins'] ) {
			$form  = '<h4 id="secupress-fix-inactive-plugins">' . __( 'Checked plugins will be deleted:', 'secupress' ) . '</h4>';
			$form .= '<fieldset aria-labelledby="secupress-fix-inactive-plugins" class="secupress-boxed-group">';

				foreach ( $lists['plugins'] as $plugin_file => $plugin_data ) {
					$is_symlinked = static::is_plugin_symlinked( $plugin_file );
					$form .= '<input type="checkbox" id="secupress-fix-delete-inactive-plugins-' . sanitize_html_class( $plugin_file ) . '" name="secupress-fix-delete-inactive-plugins[]" value="' . esc_attr( $plugin_file ) . '" ' . ( $is_symlinked ? 'disabled="disabled"' : 'checked="checked"' ) . '/> ';
					$form .= '<label for="secupress-fix-delete-inactive-plugins-' . sanitize_html_class( $plugin_file ) . '">';
						if ( $is_symlinked ) {
							$form .= '<del>' . esc_html( $plugin_data['Name'] ) . '</del> <span class="description">(' . __( 'symlinked', 'secupress' ) . ')</span>';
						} else {
							$form .= esc_html( $plugin_data['Name'] );
						}
					$form .= '</label><br/>';
				}

			$form .= '</fieldset>';
		}
		else {
			$form = __( 'No inactive plugins', 'secupress' );
		}

		$forms['delete-inactive-plugins'] = $form;

		if ( $lists['themes'] ) {
			$form  = '<h4 id="secupress-fix-inactive-themes">' . __( 'Checked themes will be deleted:', 'secupress' ) . '</h4>';
			$form .= '<fieldset aria-labelledby="secupress-fix-inactive-themes" class="secupress-boxed-group">';

				foreach ( $lists['themes'] as $theme_file => $theme_data ) {
					$is_symlinked = static::is_theme_symlinked( $theme_file );
					$form .= '<input type="checkbox" id="secupress-fix-delete-inactive-themes-' . sanitize_html_class( $theme_file ) . '" name="secupress-fix-delete-inactive-themes[]" value="' . esc_attr( $theme_file ) . '" ' . ( $is_symlinked ? 'disabled="disabled"' : 'checked="checked"' ) . '/> ';
					$form .= '<label for="secupress-fix-delete-inactive-themes-' . sanitize_html_class( $theme_file ) . '">';
						if ( $is_symlinked ) {
							$form .= '<del>' . esc_html( $theme_data->Name ) . '</del> <span class="description">(' . __( 'symlinked', 'secupress' ) . ')</span>';
						} else {
							$form .= esc_html( $theme_data->Name );
						}
					$form .= '</label><br/>';
				}

			$form .= '</fieldset>';
		}
		else {
			$form = __( 'No inactive themes', 'secupress' );
		}

		$forms['delete-inactive-themes'] = $form;

		return $forms;
	}


	// Return the inactive plugins and themes.

	protected static function get_inactive_plugins_and_themes() {
		global $wpdb;
		$out = array();

		if ( is_multisite() ) {
			// For multisite we need to get active plugins and themes for each blog. Here, we'll fetch both.
			$active = array( 'plugins' => array(), 'themes' => array(), );
			$blogs  = $wpdb->get_col( $wpdb->prepare( "SELECT blog_id FROM $wpdb->blogs WHERE site_id = %d", $wpdb->siteid ) );

			if ( count( $blogs ) <= 1 ) {
				// Plugins
				$this_blog_plugins = get_option( 'active_plugins', array() );

				if ( $this_blog_plugins && is_array( $this_blog_plugins ) ) {
					$active['plugins'] = array_combine( $this_blog_plugins, $this_blog_plugins );
				}

				// Theme
				$this_blog_theme = get_stylesheet();

				if ( $this_blog_theme ) {
					$active['themes'][ $this_blog_theme ] = $this_blog_theme;
				}
			} else {
				foreach ( $blogs as $blog_id ) {
					$blog_id = (int) $blog_id;
					$this_blog_actives = $wpdb->get_results( 'SELECT option_name, option_value FROM ' . $wpdb->prefix . ( $blog_id > 1 ? $blog_id . '_' : '' ) . 'options WHERE option_name = \'active_plugins\' OR option_name = \'stylesheet\'', OBJECT_K );

					// Plugins
					$this_blog_plugins = ! empty( $this_blog_actives['active_plugins']->option_value ) ? maybe_unserialize( $this_blog_actives['active_plugins']->option_value ) : array();

					if ( $this_blog_plugins && is_array( $this_blog_plugins ) ) {
						$this_blog_plugins = array_combine( $this_blog_plugins, $this_blog_plugins );
						$active['plugins'] = array_merge( $active['plugins'], $this_blog_plugins );
					}

					// Themes
					$this_blog_theme = ! empty( $this_blog_actives['stylesheet']->option_value ) ? $this_blog_actives['stylesheet']->option_value : '';

					if ( $this_blog_theme ) {
						$active['themes'][ $this_blog_theme ] = $this_blog_theme;
					}
				}
			}
		}

		// INACTIVE PLUGINS
		$out['plugins'] = get_plugins();

		if ( is_multisite() ) {
			$network_active_plugins = get_site_option( 'active_sitewide_plugins', array() );
			$network_active_plugins = is_array( $network_active_plugins ) ? $network_active_plugins : array();
			$active_plugins         = array_merge( $active['plugins'], $network_active_plugins );
		} else {
			$active_plugins = get_option( 'active_plugins', array() );
			$active_plugins = is_array( $active_plugins ) ? $active_plugins : array();
			$active_plugins = array_fill_keys( $active_plugins, 1 );
		}

		$out['plugins'] = array_diff_key( $out['plugins'], $active_plugins );

		// INACTIVE THEMES
		$out['themes'] = wp_get_themes();

		if ( is_multisite() ) {
			$active_themes = $active['themes'];
		} else {
			$active_themes   = array();
			$this_blog_theme = get_stylesheet();

			if ( $this_blog_theme ) {
				$active_themes[ $this_blog_theme ] = $this_blog_theme;
			}
		}

		// We may have child themes, we need to add their parent to the "active themes" list.
		if ( $active_themes ) {
			foreach ( $active_themes as $stylesheet ) {
				if ( isset( $out['themes'][ $stylesheet ] ) && $out['themes'][ $stylesheet ]->parent() ) {
					$parent_stylesheet = $out['themes'][ $stylesheet ]->parent()->get_stylesheet();
					$active_themes[ $parent_stylesheet ] = $parent_stylesheet;
				}
			}
		}

		$out['themes'] = array_diff_key( $out['themes'], $active_themes );

		return $out;
	}


	/*
	 * Tell if a plugin is symlinked.
	 *
	 * @param (string) $plugin_file: plugin main file path, relative to the plugins folder.
	 * return (bool)   true if the plugin is symlinked.
	 */

	protected static function is_plugin_symlinked( $plugin_file ) {
		static $plugins_dir;

		if ( ! isset( $plugins_dir ) ) {
			$plugins_dir = trailingslashit( realpath( WP_PLUGIN_DIR ) );
		}

		$plugin_path = trailingslashit( realpath( $plugins_dir . $plugin_file ) );
		return ! ( $plugin_path && 0 === strpos( $plugin_path, $plugins_dir ) );
	}


	/*
	 * Tell if a theme is symlinked.
	 *
	 * @param (string) $theme_slug: theme dir name.
	 * return (bool)   true if the theme is symlinked.
	 */

	protected static function is_theme_symlinked( $theme_slug ) {
		static $themes_dir;

		if ( ! isset( $themes_dir ) ) {
			$wp_filesystem = static::get_filesystem();
			$themes_dir    = $wp_filesystem->wp_themes_dir();
			$themes_dir    = trailingslashit( $themes_dir );
		}

		$theme_path = trailingslashit( realpath( $themes_dir . $theme_slug ) );
		return ! ( $theme_path && 0 === strpos( $theme_path, $themes_dir ) );
	}
}
