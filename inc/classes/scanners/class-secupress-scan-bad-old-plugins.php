<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Old Plugins scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Old_Plugins extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if you are using plugins that have been deleted from the official repository or not updated since two years at least.', 'secupress' );
		self::$more  = __( 'Avoid to use a plugin that have been removed from the official repository, and avoid using a plugin that have not been maintained for two years at least.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You don\'t use bad or old plugins.', 'secupress' ),
			1   => __( 'You don\'t use bad or old plugins anymore.', 'secupress' ),
			2   => __( 'All old plugins have been deleted.', 'secupress' ),
			// warning
			/* translators: %s is a file name. */
			100 => __( 'Error, could not read %s.', 'secupress' ),
			101 => __( 'No plugins selected.', 'secupress' ),
			102 => __( 'All selected plugins have been deleted (but some are still there).', 'secupress' ),
			103 => _n_noop( 'Sorry, the following plugin could not be deleted: %s.', 'Sorry, the following plugins could not be deleted: %s.', 'secupress' ),
			// bad
			/* translators: 1 is a number, 2 is a plugin name (or a list of plugin names). */
			200 => _n_noop( '<strong>%1$d</strong> plugin is <strong>no longer</strong> in the WordPress directory: %2$s.',   '<strong>%1$d</strong> plugins are <strong>no longer</strong> in the WordPress directory: %2$s.',   'secupress' ),
			/* translators: 1 is a number, 2 is a plugin name (or a list of plugin names). */
			201 => _n_noop( '<strong>%1$d</strong> plugin has not been updated <strong>for 2 years</strong> at least: %2$s.', '<strong>%1$d</strong> plugins have not been updated <strong>for 2 years</strong> at least: %2$s.', 'secupress' ),
			/* translators: %s is a plugin name. */
			202 => __( 'You should delete the plugin %s.', 'secupress' ),
			203 => _n_noop( 'Sorry, this plugin could not be deleted.', 'Sorry, those plugins could not be deleted.', 'secupress' ),
			// cantfix
			/* translators: %d is a number. */
			300 => _n_noop( '<strong>%d</strong> plugin is <strong>no longer</strong> in the WordPress directory.',   '<strong>%d</strong> plugins are <strong>no longer</strong> in the WordPress directory.',   'secupress' ),
			/* translators: %d is a number. */
			301 => _n_noop( '<strong>%d</strong> plugin has not been updated <strong>for 2 years</strong> at least.', '<strong>%d</strong> plugins have not been updated <strong>for 2 years</strong> at least.', 'secupress' ),
			/* translators: %s is a plugin name. */
			302 => __( 'You should delete the plugin %s.', 'secupress' ),
			303 => __( 'Unable to locate WordPress Plugin directory.' ), // WPi18n
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		// Plugins no longer in directory.
		$bad_plugins = static::get_installed_plugins_no_longer_in_directory();

		if ( $count = count( $bad_plugins ) ) {
			// bad
			$bad_plugins = self::wrap_in_tag( $bad_plugins, 'strong' );

			$this->add_message( 200, array( $count, $count, $bad_plugins ) );
		}

		// Plugins not updated in over 2 years.
		$bad_plugins = static::get_installed_plugins_over_2_years();

		if ( $count = count( $bad_plugins ) ) {
			// bad
			$bad_plugins = self::wrap_in_tag( $bad_plugins, 'strong' );

			$this->add_message( 201, array( $count, $count, $bad_plugins ) );
		}

		// Check for Hello Dolly existence.
		if ( static::has_hello_dolly() ) {
			// bad
			$this->add_message( 202, array( '<strong>Hello Dolly</strong>' ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		$fix_action = false;

		// Plugins no longer in directory.
		$bad_plugins = static::get_installed_plugins_no_longer_in_directory( true );

		if ( $count = count( $bad_plugins ) ) {
			// cantfix
			$this->add_fix_message( 300, array( $count, $count ) );
			$fix_action = true;
		}

		// Plugins not updated in over 2 years.
		$bad_plugins = static::get_installed_plugins_over_2_years( true );

		if ( $count = count( $bad_plugins ) ) {
			// cantfix
			$this->add_fix_message( 301, array( $count, $count ) );
			$fix_action = true;
		}

		// Byebye Dolly.
		if ( static::has_hello_dolly() ) {
			// cantfix
			$this->add_fix_message( 302, array( '<strong>Hello Dolly</strong>' ) );
			$fix_action = true;
		}

		if ( $fix_action ) {
			$this->add_fix_action( 'delete-bad-old-plugins' );
		} else {
			// good
			$this->add_fix_message( 1 );
		}

		return parent::fix();
	}


	public function manual_fix() {
		if ( ! $this->has_fix_action_part( 'delete-bad-old-plugins' ) ) {
			return parent::manual_fix();
		}

		$bad_plugins       = static::get_installed_plugins_to_remove();
		$count_bad_plugins = count( $bad_plugins );

		if ( ! $count_bad_plugins ) {
			// good
			$this->add_fix_message( 1 );
			return parent::manual_fix();
		}

		// Get the list of plugins to uninstall.
		$selected_plugins = ! empty( $_POST['secupress-fix-delete-bad-old-plugins'] ) && is_array( $_POST['secupress-fix-delete-bad-old-plugins'] ) ? array_filter( array_map( 'esc_attr', $_POST['secupress-fix-delete-bad-old-plugins'] ) ) : array();
		$selected_plugins = $selected_plugins ? array_fill_keys( $selected_plugins, 1 ) : array();
		$selected_plugins = $selected_plugins ? array_intersect_key( $bad_plugins, $selected_plugins ) : array();
		$count_selected   = count( $selected_plugins );

		if ( ! $count_selected ) {
			// warning: no plugins selected.
			$this->add_fix_message( 101 );
			return parent::manual_fix();
		}

		// Get filesystem.
		$wp_filesystem = static::get_filesystem();
		//Get the base plugin folder
		$plugins_dir = $wp_filesystem->wp_plugins_dir();

		if ( empty( $plugins_dir ) ) {
			// cantfix: plugins dir not located.
			$this->add_fix_message( 303 );
			return parent::manual_fix();
		}

		$plugins_dir = trailingslashit( $plugins_dir );

		// MULTISITE ===============
		if ( is_multisite() ) {
			$this->manual_fix_multisite( $bad_plugins, $count_bad_plugins, $selected_plugins, $count_selected, $wp_filesystem, $plugins_dir );
			return parent::manual_fix();
		}

		// MONOSITE ================
		ob_start();

		// Deactivate
		deactivate_plugins( array_keys( $selected_plugins ), false, false );

		$deleted_plugins = array();

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

		ob_end_clean();

		$count_deleted = count( $deleted_plugins );

		// Everything's deleted, no plugins left.
		if ( $count_deleted === $count_bad_plugins ) {
			// good
			$this->add_fix_message( 2 );
		}
		// All selected plugins deleted.
		elseif ( $count_deleted === $count_selected ) {
			// "partial": some plugins still need to be deleted.
			$this->add_fix_message( 102 );
		}
		// No plugins deleted.
		elseif ( ! $count_deleted ) {
			// bad
			$this->add_fix_message( 203, array( $count_bad_plugins ) );
		}
		// Some plugins could not be deleted.
		else {
			// cantfix
			$not_removed = array_diff_key( $selected_plugins, $deleted_plugins );
			$this->add_fix_message( 103, array( count( $not_removed ), $not_removed ) );
		}

		// Force refresh of plugin update information.
		if ( $count_deleted && $current = get_site_transient( 'update_plugins' ) ) {
			$current->response = array_diff_key( $current->response, $deleted_plugins );
			set_site_transient( 'update_plugins', $current );
		}

		return parent::manual_fix();
	}


	protected function get_fix_action_template_parts() {
		$plugins = static::get_installed_plugins_to_remove();

		if ( ! $plugins ) {
			return array( 'delete-bad-old-plugins' => static::get_messages( 1 ) );
		}

		$form  = '<div class="show-input">';
			$form .= '<h4 id="secupress-fix-bad-old-plugins">' . __( 'Checked plugins will be deleted:', 'secupress' ) . '</h4>';
			$form .= '<fieldset aria-labelledby="secupress-fix-bad-old-plugins" class="secupress-boxed-group">';

				foreach ( $plugins as $plugin_file => $plugin_name ) {
					$is_symlinked = static::is_plugin_symlinked( $plugin_file );
					$form .= '<input type="checkbox" id="secupress-fix-delete-bad-old-plugins-' . sanitize_html_class( $plugin_file ) . '" name="secupress-fix-delete-bad-old-plugins[]" value="' . esc_attr( $plugin_file ) . '" ' . ( $is_symlinked ? 'disabled="disabled"' : 'checked="checked"' ) . '/> ';
					$form .= '<label for="secupress-fix-delete-bad-old-plugins-' . sanitize_html_class( $plugin_file ) . '">';
						if ( $is_symlinked ) {
							$form .= '<del>' . esc_html( $plugin_name ) . '</del> <span class="description">(' . __( 'symlinked', 'secupress' ) . ')</span>';
						} else {
							$form .= esc_html( $plugin_name );
						}
					$form .= '</label><br/>';
				}

			$form .= '</fieldset>';
		$form .= '</div>';

		return array( 'delete-bad-old-plugins' => $form );
	}


	/*--------------------------------------------------------------------------------------------*/
	/* MULTISITE ================================================================================ */
	/*--------------------------------------------------------------------------------------------*/

	protected function manual_fix_multisite( $bad_plugins, $count_bad_plugins, $selected_plugins, $count_selected, $wp_filesystem, $plugins_dir ) {
		////
	}


	/*--------------------------------------------------------------------------------------------*/
	/* TOOLS ==================================================================================== */
	/*--------------------------------------------------------------------------------------------*/

	// All plugins to remove.

	final protected function get_installed_plugins_to_remove() {
		$plugins = array();

		// Plugins no longer in directory.
		$tmp = static::get_installed_plugins_no_longer_in_directory( true );
		if ( $tmp ) {
			$plugins = $tmp;
		}

		// Plugins not updated in over 2 years.
		$tmp = static::get_installed_plugins_over_2_years( true );
		if ( $tmp ) {
			$plugins = array_merge( $plugins, $tmp );
		}

		// Byebye Dolly.
		$tmp = static::has_hello_dolly();
		if ( $tmp ) {
			$plugins = array_merge( $plugins, $tmp );
		}

		return $plugins;
	}


	// Plugins no longer in directory - http://plugins.svn.wordpress.org/no-longer-in-directory/trunk/

	final protected static function get_installed_plugins_no_longer_in_directory( $for_fix = false ) {
		$plugins_list_file = 'data/no-longer-in-directory-plugin-list.txt';
		return static::get_installed_bad_plugins( $plugins_list_file, $for_fix );
	}


	// Plugins not updated in over 2 years - http://plugins.svn.wordpress.org/no-longer-in-directory/trunk/

	final protected static function get_installed_plugins_over_2_years( $for_fix = false ) {
		$plugins_list_file = 'data/not-updated-in-over-two-years-plugin-list.txt';
		return static::get_installed_bad_plugins( $plugins_list_file, $for_fix );
	}


	// Return an array of plugin names like `array( $path => $name, $path => $name )`.

	final protected static function get_installed_bad_plugins( $plugins_list_file, $for_fix = false ) {
		$plugins_list_file = SECUPRESS_INC_PATH . $plugins_list_file;

		if ( ! is_readable( $plugins_list_file ) ) {
			// warning
			if ( $for_fix ) {
				$this->add_fix_message( 100, array( '<code>' . str_replace( ABSPATH, '', $plugins_list_file ) . '</code>' ) );
			} else {
				$this->add_message( 100, array( '<code>' . str_replace( ABSPATH, '', $plugins_list_file ) . '</code>' ) );
			}
			return false;
		}

		$plugins_by_path  = get_plugins();
		$not_in_directory = array_flip( array_map( 'trim', file( $plugins_list_file ) ) );
		$bad_plugins      = array();

		foreach ( $plugins_by_path as $plugin_path => $plugin_data ) {
			if ( preg_match( '/([^\/]+)\//', $plugin_path, $matches ) ) {
				if ( isset( $not_in_directory[ $matches[1] ] ) ) {
					$bad_plugins[ $plugin_path ] = $plugin_data['Name'];
				}
			}
		}

		return $bad_plugins;
	}


	// Dolly are you here?

	final protected static function has_hello_dolly() {
		$plugins = array();

		if ( file_exists( WP_PLUGIN_DIR . '/hello.php' ) ) {
			$plugins['hello.php'] = 'Hello Dolly';
		}

		if ( file_exists( WP_PLUGIN_DIR . '/hello-dolly/hello.php' ) ) {
			$plugins['hello-dolly/hello.php'] = 'Hello Dolly' . ( $plugins ? ' (' . __( 'from the official repository', 'secupress' ) . ')' : '' );
		}

		return $plugins;
	}


	/*
	 * Tell if a plugin is symlinked.
	 *
	 * @param (string) $plugin_file: plugin main file path, relative to the plugins folder.
	 * return (bool)   true if the plugin is symlinked.
	 */
	final protected static function is_plugin_symlinked( $plugin_file ) {
		$plugin_path = realpath( WP_PLUGIN_DIR . '/' . $plugin_file );
		return ! ( $plugin_path && 0 === strpos( $plugin_path, WP_PLUGIN_DIR . '/' ) );
	}
}
