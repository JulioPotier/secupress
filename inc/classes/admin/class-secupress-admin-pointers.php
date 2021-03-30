<?php
/**
 * Administration API: SecuPress_Admin_Pointers class
 *
 * @since 2.0
 */

/**
 * Core class used to implement an internal admin pointers API.
 *
 * @since 2.0
 */
final class SecuPress_Admin_Pointers {

	/**
	 * Initializes the new feature pointers.
	 *
	 * @since 2.0
	 *
	 * All pointers can be disabled using the following:
	 *     remove_action( 'admin_enqueue_scripts', array( 'SecuPress_Admin_Pointers', 'enqueue_scripts' ) );
	 *
	 * Individual pointers (e.g. spxx_foobar) can be disabled using the following:
	 *     remove_action( 'admin_print_footer_scripts', array( 'SecuPress_Admin_Pointers', 'pointer_spxx_foobar' ) );
	 *
	 * @static
	 *
	 * @param string $hook_suffix The current admin page.
	 */
	public static function enqueue_scripts( $hook_suffix ) {
		if ( ! secupress_get_capability() ) {
			return;
		}
		/*
		 * Register feature pointers
		 *
		 * Format:
		 *     array(
		 *         hook_suffix => pointer callback
		 *     )
		 *
		 * Example:
		 *     array(
		 *         'plugins.php' => 'spxx_foobar',
		 *         'secupress_page_secupress_xx' => 'spxx_foobar'
		 *     )
		 */
		$registered_pointers = [
			'secupress_page_secupress_modules' => [
				'any'            => [ 'sp20_ad1month', 'sp20_addonszz' ],
				'sensitive-data' => [ 'sp20_404guess' ],
				'welcome'        => [ 'sp20_advanced' ],
				'users-login'    => [ 'sp20_lockedzz' ],
				'wordpress-core' => [ 'sp20_dbprefix', 'sp20_wpconfig' ],
				'file-system'    => [ 'sp20_malwares' ],
				'alerts'         => [ 'sp20_slacknot' ],
			],
		];
		// Check if screen related pointer is registered.
		if ( ! isset( $registered_pointers[ $hook_suffix ] ) ) {
			return;
		}
		$pointers     = isset( $registered_pointers[ $hook_suffix ]['any'] ) ? $registered_pointers[ $hook_suffix ]['any'] : [];
		$module       = isset( $_GET['module'] ) ? sanitize_key( $_GET['module' ] ) : 'any'; // Do not translate.
		if ( isset( $registered_pointers[ $hook_suffix ][ $module ] ) ) {
			$pointers = array_merge( $pointers, $registered_pointers[ $hook_suffix ][ $module ] );
		}
		$dismissed    = explode( ',', (string) get_user_meta( get_current_user_id(), 'dismissed_wp_pointers', true ) );
		$pointers     = array_diff( $pointers, $dismissed );
		// Limit pointers to 2 per screenn order by the natural array order
		$pointers     = array_slice( $pointers, 0, 2 );
		foreach ( $pointers as $pointer ) {
			// Bind pointer print function
			add_action( 'admin_print_footer_scripts', array( 'SecuPress_Admin_Pointers', 'pointer__' . $pointer ) );
			// Add pointers script and style to queue
			wp_enqueue_style( 'wp-pointer' );
			wp_enqueue_script( 'wp-pointer' );
			add_action( 'admin_print_footer_scripts', array( 'SecuPress_Admin_Pointers', 'print_pointer_css_rules' ) );
		}

	}

	/**
	 * Print the pointer JavaScript data.
	 *
	 * @since 2.0
	 *
	 * @static
	 *
	 * @param string $pointer_id The pointer ID.
	 * @param string $selector The HTML elements, on which the pointer should be attached.
	 * @param array  $args Arguments to be passed to the pointer JS (see wp-pointer.js).
	 */
	private static function print_js( $pointer_id, $selector, $args ) {
		if ( empty( $pointer_id ) || empty( $selector ) || empty( $args ) || empty( $args['content'] ) )
			return;
		?>
		<script type="text/javascript">
		(function($){
			var options = <?php echo wp_json_encode( $args ); ?>, setup;

			if ( ! options )
				return;

			options = $.extend( options, {
				close: function() {
					$.post( ajaxurl, {
						pointer: '<?php echo $pointer_id; ?>',
						_ajaxnonce: '<?php echo wp_create_nonce( "dismiss-pointer_{$pointer_id}" ); ?>',
						action: 'dismiss-sp-pointer'
					});
				}
			});

			setup = function() {
				$('<?php echo $selector; ?>').first().pointer( options ).pointer('open');
			};

			if ( options.position && options.position.defer_loading )
				$(window).bind( 'load.wp-pointers', setup );
			else
				$(document).ready( setup );

		})( jQuery );
		</script>
		<?php
	}

	/**
	 * Print the pointer CSS rules.
	 * Don't add those pointers in CSS because they will change the WP one and we cannot add a prefix, just print it.
	 *
	 * @since 2.0
	 *
	 * @static
	 */
	public static function print_pointer_css_rules() {
	?>
		<style>
		.wp-pointer .wp-pointer-content h3 {
			background-color: #26B3A9;
			border-color: #26B3A9;
			padding: 15px 18px 14px 12px;
		}
		.wp-pointer .wp-pointer-content h3 .dashicons {
			font-size: 2em;
			vertical-align: text-bottom;
			margin-right: 7px;
			margin-top: -6px;
			padding: 2px
		}
		.wp-pointer .wp-pointer-content h3 .dashicons-heart {
			color: #CA4A1F;
		}
		.wp-pointer .wp-pointer-content h3 .dashicons-star-filled {
			color: #F1C40F;
		}
		.wp-pointer .wp-pointer-content h3 .dashicons-money-alt {
			color: #FF0;
		}
		.wp-pointer .wp-pointer-content h3:before {
			display: none;
		}
		</style>
	<?php
	}

	/**
	 * New feature 404 guessing
	 *
	 * @since 2.0
	 */
	public static function pointer__sp20_404guess() {
		$content  = '<h3><span class="dashicons dashicons-star-filled"></span> ' . __( 'New SecuPress Pro Feature', 'secupress' ) . '</h3>';
		$content .= '<h4>' . __( 'Anti 404 Guessing', 'secupress' ) . '</h4>';

		$position = array(
			'edge'  => 'right',
			'align' => 'bottom',
		);

		$js_args = array(
			'content'  => $content,
			'position' => $position,
			'pointerClass' => 'wp-pointer arrow-bottom',
			/** Translators: Format 'ddd%' or 'ddd', not 'px' */
			'pointerWidth' => _x( '400', 'pointerWidth', 'secupress' ),
		);
		self::print_js( str_replace( 'pointer__', '', __FUNCTION__ ), '.secupress-setting-row_content-protect_404guess', $js_args );
	}

	/**
	 * New ad, try SP pro 1 month
	 *
	 * @since 2.0
	 */
	public static function pointer__sp20_ad1month() {
		$content  = '<h3><span class="dashicons dashicons-money-alt"></span> ' . __( 'Special Offer: <strike>69$/year</strike> 6$!', 'secupress' ) . '</h3>';
		$content .= '<h4>' . __( 'Try SecuPress Pro for 1 Month for 6$', 'secupress' ) . '</h4>';
		$content .= '<p>' . __( 'Use the discount code <code>SP1MONTH</code> to get a 1st month of SecuPress Pro for only 6$, cancel anytime.', 'secupress' ) . '</p>';

		$position = array(
			'edge'  => 'right',
			'align' => 'top',
		);

		$js_args = array(
			'content'  => $content,
			'position' => $position,
			'pointerClass' => 'wp-pointer arrow-bottom',
			/** Translators: Format 'ddd%' or 'ddd', not 'px' */
			'pointerWidth' => _x( '400', 'pointerWidth', 'secupress' ),
		);
		self::print_js( str_replace( 'pointer__', '', __FUNCTION__ ), '.secupress-pro-ad', $js_args );
	}

	/**
	 * New addons module
	 *
	 * @since 2.0
	 */
	public static function pointer__sp20_addonszz() {
		if ( isset( $_GET['module'] ) && 'addons' === $_GET['module'] ) {
			secupress_dismiss_pointer_admin_post_cb( 'sp20_addonszz' );
			return;
		}

		$content  = '<h3><span class="dashicons dashicons-heart"></span> ' . __( 'New Module: Addons', 'secupress' ) . '</h3>';
		$content .= '<h4>' . __( 'Discover our 2 brand new recommandations.', 'secupress' ) . '</h4>';

		$position = array(
			'edge'  => 'left',
			'align' => 'bottom',
		);

		$js_args = array(
			'content'  => $content,
			'position' => $position,
			'pointerClass' => 'wp-pointer arrow-bottom',
			/** Translators: Format 'ddd%' or 'ddd', not 'px' */
			'pointerWidth' => _x( '400', 'pointerWidth', 'secupress' ),
		);
		self::print_js( str_replace( 'pointer__', '', __FUNCTION__ ), '.module-addons', $js_args );
	}

	/**
	 * New advanced settings
	 *
	 * @since 2.0
	 */
	public static function pointer__sp20_advanced() {
		$content  = '<h3><span class="dashicons dashicons-shield-alt"></span> ' . __( 'New SecuPress Free Features', 'secupress' ) . '</h3>';
		$content .= '<h4>' . __( 'Advanced Settings', 'secupress' ) . '</h4>';
		$content .= '<p>' . __( 'You can now hide the <em>Admin Bar Menu</em> from SecuPress and disable the <em>Grade System</em>.', 'secupress' ) . '</p>';

		$position = array(
			'edge'  => 'right',
			'align' => 'top',
		);

		$js_args = array(
			'content'  => $content,
			'position' => $position,
			'pointerClass' => 'wp-pointer arrow-bottom',
			/** Translators: Format 'ddd%' or 'ddd', not 'px' */
			'pointerWidth' => _x( '400', 'pointerWidth', 'secupress' ),
		);
		self::print_js( str_replace( 'pointer__', '', __FUNCTION__ ), '#secupress-settings-module_welcome--secupress_advanced_settings', $js_args );
	}

	/**
	 * New locked features
	 *
	 * @since 2.0
	 */
	public static function pointer__sp20_lockedzz() {
		$content  = '<h3><span class="dashicons dashicons-shield-alt"></span> ' . __( 'New SecuPress Free Features', 'secupress' ) . '</h3>';
		$content .= '<h4>' . __( 'Lock Sensible WP Settings', 'secupress' ) . '</h4>';
		$content .= '<p>' . __( 'You can now lock the <em>Default Role Setting</em>, the <em>Subscription Setting</em>, and the <em>Admin Email Setting</em>.', 'secupress' ) . '</p>';

		$position = array(
			'edge'  => 'right',
			'align' => 'bottom',
		);

		$js_args = array(
			'content'  => $content,
			'position' => $position,
			'pointerClass' => 'wp-pointer arrow-top',
			/** Translators: Format 'ddd%' or 'ddd', not 'px' */
			'pointerWidth' => _x( '400', 'pointerWidth', 'secupress' ),
		);
		self::print_js( str_replace( 'pointer__', '', __FUNCTION__ ), '.secupress-setting-row_blacklist-logins_default-role-activated', $js_args );
	}

	/**
	 * New db prefix change
	 *
	 * @since 2.0
	 */
	public static function pointer__sp20_dbprefix() {
		$dashicon = secupress_has_pro() ? '<span class="dashicons dashicons-star-filled"></span>' : '<span class="dashicons dashicons-privacy"></span>';
		$content  = '<h3>' . $dashicon . ' ' . __( 'New SecuPress Pro Feature', 'secupress' ) . '</h3>';
		$content .= '<h4>' . __( 'Change WordPress Database Prefix', 'secupress' ) . '</h4>';
		$content .= '<p>' . __( 'You can now manually change the <em>WordPress Database Prefix</em> on demand.', 'secupress' ) . '</p>';

		$position = array(
			'edge'  => 'right',
			'align' => 'top',
		);

		$js_args = array(
			'content'  => $content,
			'position' => $position,
			'pointerClass' => 'wp-pointer arrow-bottom',
			/** Translators: Format 'ddd%' or 'ddd', not 'px' */
			'pointerWidth' => _x( '400', 'pointerWidth', 'secupress' ),
		);
		self::print_js( str_replace( 'pointer__', '', __FUNCTION__ ), '#module-database', $js_args );
	}

	/**
	 * New malware scan
	 *
	 * @since 2.0
	 */
	public static function pointer__sp20_malwares() {
		$dashicon = secupress_has_pro() ? '<span class="dashicons dashicons-star-filled"></span>' : '<span class="dashicons dashicons-privacy"></span>';
		$content  = '<h3>' . $dashicon . ' ' . __( 'Revamped SecuPress Pro Feature', 'secupress' ) . '</h3>';
		$content .= '<h4>' . __( 'New Malware Scan Data', 'secupress' ) . '</h4>';
		$content .= '<p>' . __( 'Our scanner is now way more <strong>accurate</strong>, will display <strong>Malware Signatures</strong> and comes with 95% less false positives!', 'secupress' ) . '</p>';

		$position = array(
			'edge'  => 'right',
			'align' => 'bottom',
		);

		$js_args = array(
			'content'  => $content,
			'position' => $position,
			'pointerClass' => 'wp-pointer arrow-top',
			/** Translators: Format 'ddd%' or 'ddd', not 'px' */
			'pointerWidth' => _x( '400', 'pointerWidth', 'secupress' ),
		);
		self::print_js( str_replace( 'pointer__', '', __FUNCTION__ ), '#secupress-settings-module_file-system--file-scanner', $js_args );
	}

	/**
	 * New Slack Notifications
	 *
	 * @since 2.0
	 */
	public static function pointer__sp20_slacknot() {
		$dashicon = secupress_has_pro() ? '<span class="dashicons dashicons-star-filled"></span>' : '<span class="dashicons dashicons-privacy"></span>';
		$content  = '<h3>' . $dashicon . ' ' . __( 'New SecuPress Pro Feature', 'secupress' ) . '</h3>';
		$content .= '<h4>' . __( 'Slack Webhook Notifications', 'secupress' ) . '</h4>';
		$content .= '<p>' . __( 'You can now send the SecuPress alerts directly in your favorite Slack team and Channel.', 'secupress' ) . '</p>';

		$position = array(
			'edge'  => 'right',
			'align' => 'top',
		);

		$js_args = array(
			'content'  => $content,
			'position' => $position,
			'pointerClass' => 'wp-pointer arrow-top',
			/** Translators: Format 'ddd%' or 'ddd', not 'px' */
			'pointerWidth' => _x( '400', 'pointerWidth', 'secupress' ),
		);
		self::print_js( str_replace( 'pointer__', '', __FUNCTION__ ), '#row-notification-types_slack', $js_args );
	}

	/**
	 * New wp config values
	 *
	 * @since 2.0
	 */
	public static function pointer__sp20_wpconfig() {
		$content  = '<h3><span class="dashicons dashicons-shield-alt"></span> ' . __( 'New SecuPress Free Features', 'secupress' ) . '</h3>';
		$content .= '<h4>' . __( '7 new features', 'secupress' ) . '</h4>';
		$content .= '<p>' . __( 'You can now protect your <em>Website Addresses</em>, your <em>DB Repair Page</em>, your <em>Database Errors Display</em>, your <em>Debug Settings</em>, your <em>Default Cookie Name</em> and manually change your <em>WordPress Security Keys</em>.', 'secupress' ) . '</p>';

		$position = array(
			'edge'  => 'right',
			'align' => 'top',
		);

		$js_args = array(
			'content'  => $content,
			'position' => $position,
			'pointerClass' => 'wp-pointer arrow-top',
			/** Translators: Format 'ddd%' or 'ddd', not 'px' */
			'pointerWidth' => _x( '400', 'pointerWidth', 'secupress' ),
		);
		self::print_js( str_replace( 'pointer__', '', __FUNCTION__ ), '#secupress-settings-module_wordpress-core--wp_config', $js_args );
	}

	/**
	 * Prevents new users from seeing existing pointers.
	 *
	 * @since 2.0
	 *
	 * @static
	 *
	 * @param int $user_id User ID.
	 */
	public static function dismiss_pointers_for_new_users( $user_id ) {
		// add_user_meta( $user_id, 'dismissed_wp_pointers', 'spxx_foobar' );
	}
}
