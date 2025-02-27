<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Bad Old Themes scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 2.2.6
 */
class SecuPress_Scan_Bad_Old_Themes extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '2.2.6';


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
	 * @since 2.2.6
	 */
	protected function init() {
		$this->title = __( 'Check if you are using themes that have been deleted from the official repository or have not been updated for at least two years.', 'secupress' );
		$this->more  = __( 'Do not use a theme that has been closed on the official repository, and prevent usage of themes that have not been maintained for two years at least.', 'secupress' );

		if ( is_network_admin() ) {
			$this->more_fix  = __( 'Select closed and old themes to be deleted.', 'secupress' );
			$this->more_fix .= '<br/>' . __( 'Not fixable on Multisite.', 'secupress' );
			$this->fixable   = false;
		} elseif ( ! is_multisite() ) {
			$this->more_fix = __( 'Select and delete closed and old themes', 'secupress' );
		} else {
			$this->more_fix = __( 'Delete closed and old themes', 'secupress' );
		}
	}


	/**
	 * Get messages.
	 *
	 * @since 2.2.6
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		$messages = [
			// "good"
			0   => __( 'You don’t use closed or old themes', 'secupress' ),
			1   => __( 'You don’t use closed or old themes anymore.', 'secupress' ),
			2   => __( 'All deletable closed or old themes have been deleted.', 'secupress' ),
			/** Translators: %s is a file name. */
			100 => __( 'Error, could not read %s.', 'secupress' ),
			101 => __( 'No themes selected for deletion.', 'secupress' ),
			102 => _n_noop( 'Selected theme has been deleted (but some are still there).', 'All selected themes have been deleted (but some are still there).', 'secupress' ),
			103 => _n_noop( 'Sorry, the following theme could not be deleted: %s.', 'Sorry, the following themes could not be deleted: %s.', 'secupress' ),
			/** Translators: %s is the theme name. */
			104 => sprintf( __( 'You have a big network, %s must work on some data before being able to perform this scan.', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ),
			110 => __( 'Your installation may contain old or closed plugins. The PRO version will be more accurate.', 'secupress' ),
			// "bad"
			/** Translators: 1 is a number, 2 is a theme name (or a list of theme names). */
			200 => _n_noop( '<strong>%1$d theme</strong> is no longer in the WordPress repository: %2$s.', '<strong>%1$d themes</strong> are no longer in the WordPress repository: %2$s.', 'secupress' ),
			/** Translators: 1 is a number, 2 is a theme name (or a list of theme names). */
			201 => _n_noop( '<strong>%1$d theme</strong> has not been updated for at least 2 years: %2$s.', '<strong>%1$d themes</strong> have not been updated for at least 2 years: %2$s.', 'secupress' ),
			/** Translators: %s is a theme name. */
			202 => _n_noop( 'The following theme should be deleted if you don’t need it: %s.', 'The following themes should be deleted if you don’t need them: %s.', 'secupress' ),
			203 => _n_noop( 'Sorry, this theme could not be deleted.', 'Sorry, those themes could not be deleted.', 'secupress' ),
			// "cantfix"
			301 => __( 'No themes selected.', 'secupress' ),
			302 => __( 'Unable to locate WordPress Theme folder', 'secupress' ),
			/** Translators: %s is the theme name. */
			303 => sprintf( __( 'A new %s menu item has been activated in the relevant site’s administration area to let Administrators know which themes to delete', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ),
		];

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Getters. ================================================================================ */

	/**
	 * Get the documentation URL.
	 *
	 * @since 2.2.6
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'https://docs.secupress.me/article/232-outdated-closed-and-vulnerable-theme-check', 'secupress' );
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 2.2.6
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
			$this->add_message( 104 );
			return parent::scan();
		}

		// Multisite, for the current site.
		if ( $this->is_for_current_site() ) {
			// Themes no longer in directory or not updated in over 2 years.
			$bad_themes = $this->get_installed_themes_to_remove();

			if ( $count = count( $bad_themes ) ) {
				// "bad"
				$this->add_message( 202, array( $count, $bad_themes ) );
			}
		}
		// Network admin or not Multisite.
		else {
			// If we're in a sub-site, don't list the themes enabled in the network.
			$to_keep   = [];

			// Themes no longer in directory.
			$bad_themes = $this->get_closed_themes();
			$count      = is_array( $bad_themes ) ? count( $bad_themes ) : false;

			if ( false === $count ) {
				// "warning"
				if ( secupress_is_pro() ) {
					$this->add_message( 100, array( _x( 'data', 'Error, could not read data.', 'secupress' ) ) );
				} else {
					$this->add_message( 110 );
				}
			}

			if ( $count > 0 ) {
				// "bad"
				$this->add_message( 200, array( $count, $count, self::wrap_in_tag( $bad_themes ) ) );
			}

			// Themes not updated in over 2 years.
			$bad_themes = $this->get_old_themes();
			$bad_themes = $to_keep ? array_diff_key( $bad_themes, $to_keep ) : $bad_themes;
			$count      = is_array( $bad_themes ) ? count( $bad_themes ) : false;

			if ( false === $count ) {
				// "warning"
				if ( secupress_is_pro() ) {
					$this->add_message( 100, array( _x( 'data', 'Error, could not read data.', 'secupress' ) ) );
				} else {
					$this->add_message( 110 );
				}
			}

			if ( $count > 0 ) {
				// "bad"
				$this->add_message( 201, array( $count, $count, self::wrap_in_tag( $bad_themes ) ) );
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
	 * @since 2.2.6
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
	 * @since 2.2.6
	 *
	 * @return (array)
	 */
	public function need_manual_fix() {
		$bad_themes = $this->get_installed_themes_to_remove();
		$actions    = [];

		if ( count( $bad_themes ) ) {
			$actions['delete-bad-old-themes'] = 'delete-bad-old-themes';
		}

		return $actions;
	}


	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 2.2.6
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		$bad_themes = $this->get_installed_themes_to_remove();

		if ( count( $bad_themes ) ) {
			// DELETE THEMES.
			if ( $this->has_fix_action_part( 'delete-bad-old-themes' ) ) {
				$delete = $this->manual_delete( $bad_themes );
			}

			if ( ! empty( $delete ) ) {
				// "cantfix": nothing selected in lists.
				$this->add_fix_message( $delete );
			}
		} else {
			// "good"
			$this->add_fix_message( 1 );
		}

		return parent::manual_fix();
	}


	/**
	 * Manual fix to delete themes.
	 *
	 * @since 2.2.6
	 *
	 * @param (array) $bad_themes An array of bad_themes to delete. Values must be sanitized before.
	 */
	protected function manual_delete( $bad_themes ) {
		if ( ! $bad_themes ) {
			// "good"
			return $this->add_fix_message( 1 );
		}

		// Get the list of bad_themes to uninstall.
		$selected_themes = ! empty( $_POST['secupress-fix-delete-bad-old-themes'] ) && is_array( $_POST['secupress-fix-delete-bad-old-themes'] ) ? array_filter( $_POST['secupress-fix-delete-bad-old-themes'] ) : []; // WPCS: CSRF ok.
		$selected_themes = $selected_themes ? array_fill_keys( $selected_themes, 1 ) : [];
		$selected_themes = $selected_themes ? array_intersect_key( $bad_themes, $selected_themes ) : []; // Sanitize submitted values.

		if ( ! $selected_themes ) {
			if ( $this->has_fix_action_part( 'delete-bad-old-themes' ) ) {
				/*
				 * "warning": no themes selected.
				 * No `add_fix_message()`, we need to change the status from warning to cantfix if both lists have no selection.
				 */
				return 101;
			}
			// "cantfix": no themes selected.
			return $this->add_fix_message( 301 );
		}

		// Get filesystem.
		$wp_filesystem = secupress_get_filesystem();
		// Get the base theme folder.
		$themes_dir = $wp_filesystem->wp_themes_dir();

		if ( empty( $themes_dir ) ) {
			// "cantfix": themes dir not located.
			return $this->add_fix_message( 302 );
		}

		$themes_dir = trailingslashit( $themes_dir );

		$themes_translations = wp_get_installed_translations( 'themes' );

		ob_start();

		$deleted_themes = [];

		foreach ( $selected_themes as $theme_file => $dummy ) {

			/** This action is documented in wp-admin/includes/theme.php */
			do_action( 'delete_theme', $theme_file );

			$this_theme_dir = trailingslashit( dirname( $themes_dir . $theme_file ) );

			// If theme is in its own directory, recursively delete the directory.
			if ( strpos( $theme_file, '/' ) && $this_theme_dir !== $themes_dir ) { // base check on if theme includes directory separator AND that its not the root theme folder.
				$deleted = $wp_filesystem->delete( $this_theme_dir, true );
			} else {
				$deleted = $wp_filesystem->delete( $themes_dir . $theme_file );
			}

			/** This action is documented in wp-admin/includes/theme.php */
			do_action( 'deleted_theme', $theme_file, $deleted );

			if ( $deleted ) {
				$deleted_themes[ $theme_file ] = 1;

				// Remove language files, silently.
				$theme_slug = dirname( $theme_file );

				if ( '.' !== $theme_slug && ! empty( $themes_translations[ $theme_slug ] ) ) {
					$translations = $themes_translations[ $theme_slug ];

					foreach ( $translations as $translation => $data ) {
						$wp_filesystem->delete( WP_LANG_DIR . '/themes/' . $theme_slug . '-' . $translation . '.po' );
						$wp_filesystem->delete( WP_LANG_DIR . '/themes/' . $theme_slug . '-' . $translation . '.mo' );
					}
				}
			}
		}

		ob_end_clean();
		// Everything's deleted, no themes left.
		if ( ! array_diff_key( $bad_themes, $deleted_themes ) ) {
			// "good"
			$this->add_fix_message( 2 );
		}
		// All selected themes deleted.
		elseif ( ! array_diff_key( $deleted_themes, $selected_themes ) ) {
			// "partial": some themes still need to be deleted.
			$this->add_fix_message( 102, array( count( $selected_themes ) ) );
		}
		// No themes deleted.
		elseif ( ! $deleted_themes ) {
			// "bad"
			$this->add_fix_message( 203, array( count( $bad_themes ) ) );
		}
		// Some themes could not be deleted.
		else {
			// "cantfix"
			$not_removed = array_diff_key( $selected_themes, $deleted_themes );
			$not_removed = array_map( 'strip_tags', $not_removed );
			$not_removed = array_map( 'esc_html', $not_removed );
			$this->add_fix_message( 103, array( count( $not_removed ), $not_removed ) );
		}

		// Force refresh of theme update information and cache.
		if ( $deleted_themes ) {
			if ( $current = get_site_transient( 'update_themes' ) ) {
				$current->response  = array_diff_key( $current->response, $deleted_themes );
				$current->no_update = array_diff_key( $current->no_update, $deleted_themes );
				set_site_transient( 'update_themes', $current );
			}

			wp_cache_delete( 'themes', 'themes' );
		}
	}

	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 2.2.6
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		$themes = $this->get_installed_themes_to_remove();
		$out    = [
			'delete-bad-old-themes'     => static::get_messages( 1 ),
		];

		if ( count( $themes ) ) {
			$form  = '<h4 id="secupress-fix-bad-old-themes">' . __( 'Checked themes will be deleted:', 'secupress' ) . '</h4>';
			$form .= '<fieldset aria-labelledby="secupress-fix-bad-old-themes" class="secupress-boxed-group">';
			$theme = wp_get_theme();
			var_dump($themes);
			var_dump($theme->template);
			var_dump($theme->stylesheet);
			foreach ( $themes as $theme_slug => $theme_name ) {
				$theme_name = esc_html( strip_tags( $theme_name ) );
				if ( $theme_slug !== $theme->template && $theme_slug !== $theme->stylesheet ) {
					$form .= '<input type="checkbox" id="secupress-fix-delete-bad-old-themes-' . sanitize_html_class( $theme_slug ) . '" name="secupress-fix-delete-bad-old-themes[]" value="' . esc_attr( $theme_slug ) . '" checked="checked"' . '/> ';
				} else {
					$form .= '<input type="checkbox" id="secupress-fix-delete-bad-old-themes-' . sanitize_html_class( $theme_slug ) . '" disabled="disabled"' . '/>';
				}
				$form .= '<label for="secupress-fix-delete-bad-old-themes-' . sanitize_html_class( $theme_slug ) . '">';
				$form .= "<strong>$theme_name</strong>";
				if ( $theme_slug === $theme->template || $theme_slug === $theme->stylesheet ) {
					$form .= ' <em>(' . __( 'Active theme, switch your theme before!', 'secupress' ) . ')</em>';
				}
				$form .= '</label><br/>';
			}

			$form .= '</fieldset>';

			$out['delete-bad-old-themes'] = $form;
		}

		return $out;
	}


	/** Tools. ================================================================================== */

	/**
	 * Get all themes to delete.
	 *
	 * @since 2.2.6
	 *
	 * @return (array).
	 */
	final protected function get_installed_themes_to_remove() {
		$themes = [];

		// Themes no longer in directory.
		$tmp = $this->get_closed_themes( true );
		if ( $tmp ) {
			$themes = $tmp;
		}

		// Themes not updated in over 2 years.
		$tmp = $this->get_old_themes( true );
		if ( $tmp ) {
			$themes = array_merge( $themes, $tmp );
		}

		return $themes;
	}


	/**
	 * Get themes no longer in directory.
	 *
	 * @since 2.2.6
	 *
	 * @param (bool) $for_fix False: for scan. True: for fix.
	 *
	 * @return (array).
	 */
	final protected function get_closed_themes( $for_fix = false ) {
		return $this->get_installed_bad_themes( 'closed', $for_fix );
	}


	/**
	 * Get themes not updated in over 2 years.
	 *
	 * @since 2.2.6
	 *
	 * @param (bool) $for_fix False: for scan. True: for fix.
	 *
	 * @return (array).
	 */
	final protected function get_old_themes( $for_fix = false ) {
		return $this->get_installed_bad_themes( 'old', $for_fix );
	}


	/**
	 * Get an array of installed "bad" themes
	 *
	 * @since 2.2.6
	 *
	 * @param (string) $themes_type "closed" or "old".
	 * @param (bool)   $for_fix      False: for scan. True: for fix.
	 *
	 * @return (array) An array like `array( path => theme_name, path => theme_name )`.
	 */
	final protected function get_installed_bad_themes( $themes_type, $for_fix = false ) {
		$bad_themes  = secupress_get_bad_themes( $themes_type );
		if ( ! $bad_themes ) {
			return [];
		}

		$all_themes = wp_get_themes();
		$bad_themes = array_intersect_key( $all_themes, $bad_themes );
		$bad_themes = wp_list_pluck( $bad_themes, 'Name' );

		return $bad_themes;
	}

}
