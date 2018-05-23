<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Modules settings class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Settings
 * @since 1.0
 */
class SecuPress_Settings_Modules extends SecuPress_Settings {

	const VERSION = '1.0';

	/**
	 * All the modules, with (mainly) title, icon, description.
	 *
	 * @var (array)
	 */
	protected static $modules;

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Setters ================================================================================= */

	/**
	 * Set the modules infos.
	 *
	 * @since 1.0
	 */
	final protected static function set_modules() {
		static::$modules = secupress_get_modules();
	}


	/**
	 * Set the current module.
	 *
	 * @since 1.0
	 *
	 * @return (object) The class instance.
	 */
	final protected function set_current_module() {
		$this->modulenow = isset( $_GET['module'] ) ? $_GET['module'] : 'welcome';
		$this->modulenow = array_key_exists( $this->modulenow, static::get_modules() ) && file_exists( SECUPRESS_MODULES_PATH . $this->modulenow . '/settings.php' ) ? $this->modulenow : 'welcome';
		return $this;
	}


	/** Getters ================================================================================= */

	/**
	 * Set the modules infos.
	 *
	 * @since 1.0
	 *
	 * @return (array) The modules.
	 */
	final public static function get_modules() {
		if ( empty( static::$modules ) ) {
			static::set_modules();
		}

		return static::$modules;
	}


	/**
	 * Get a module title.
	 *
	 * @since 1.0
	 *
	 * @param (string) $module The desired module.
	 *
	 * @return (string)
	*/
	final public function get_module_title( $module = false ) {
		$modules = static::get_modules();
		$module  = $module ? $module : $this->modulenow;

		if ( ! empty( $modules[ $module ]['title'] ) ) {
			return $modules[ $module ]['title'];
		}

		return '';
	}


	/**
	 * Get a module descriptions.
	 *
	 * @since 1.0
	 *
	 * @param (string) $module The desired module.
	 *
	 * @return (array)
	*/
	final public function get_module_descriptions( $module = false ) {
		$modules = static::get_modules();
		$module  = $module ? $module : $this->modulenow;

		if ( ! empty( $modules[ $module ]['description'] ) ) {
			return (array) $modules[ $module ]['description'];
		}

		return array();
	}


	/**
	 * Get a module summary.
	 *
	 * @since 1.0
	 *
	 * @param (string) $module The desired module.
	 * @param (string) $size The desired size: small|normal.
	 *
	 * @return (string)
	*/
	final public function get_module_summary( $module = false, $size = 'normal' ) {
		$modules = static::get_modules();
		$module  = $module ? $module : $this->modulenow;

		if ( ! empty( $modules[ $module ]['summaries'][ $size ] ) ) {
			return $modules[ $module ]['summaries'][ $size ];
		}

		return '';
	}


	/**
	 * Get a module icon.
	 *
	 * @since 1.0
	 * @author Geoffrey
	 *
	 * @param (string) $module The desired module.
	 *
	 * @return (string)
	 */
	final public function get_module_icon( $module = false ) {
		$modules = static::get_modules();
		$module  = $module ? $module : $this->modulenow;

		if ( ! empty( $modules[ $module ]['icon'] ) ) {
			return $modules[ $module ]['icon'];
		}

		return '';
	}


	/**
	 * Tells if the reset box should be displayed for a specific module.
	 *
	 * @since 1.0
	 *
	 * @param (string) $module The desired module.
	 *
	 * @return (bool)
	*/
	final public function display_module_reset_box( $module = false ) {
		$modules = static::get_modules();
		$module  = $module ? $module : $this->modulenow;

		return isset( $modules[ $module ]['with_reset_box'] ) ? (bool) $modules[ $module ]['with_reset_box'] : true;
	}


	/** Init ==================================================================================== */

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		parent::_init();

		$modules = static::get_modules();

		$this->with_form = ! ( isset( $modules[ $this->modulenow ]['with_form'] ) && false === $modules[ $this->modulenow ]['with_form'] );

		if ( secupress_is_pro() ) {
			require_once( SECUPRESS_PRO_ADMIN_PATH . 'settings.php' );
		}
	}


	/** Main template tags ====================================================================== */

	/**
	 * Print the page content.
	 *
	 * @since 1.0
	 */
	public function print_page() {
		$secupress_has_sideads = apply_filters( 'secupress.no_sidebar', true ) && apply_filters( 'secupress.no_sideads', true );
		?>
		<div class="wrap">

			<?php secupress_admin_heading( __( 'Modules', 'secupress' ) ); ?>
			<?php settings_errors(); ?>

			<div class="secupress-wrapper secupress-flex secupress-flex-top<?php echo ( $secupress_has_sideads ? ' secupress-has-sideads' : '' ) ?>">
				<div class="secupress-modules-sidebar">
					<div class="secupress-sidebar-header">
						<div class="secupress-flex">
							<div class="secupress-sh-logo">
								<?php echo secupress_get_logo(); ?>
							</div>
							<div class="secupress-sh-name">
								<p class="secupress-sh-title">
									<?php echo secupress_get_logo_word( array( 'width' => 81, 'height' => 19 ) ); ?>
								</p>
							</div>
						</div>
					</div>

					<ul id="secupress-modules-navigation" class="secupress-modules-list-links">
						<?php $this->print_tabs(); ?>
					</ul>
				</div>
				<div class="secupress-tab-content secupress-tab-content-<?php echo $this->get_current_module(); ?>" id="secupress-tab-content">
					<?php $this->print_current_module(); ?>
				</div>

				<?php $this->print_sideads(); ?>

			</div>

		</div>
		<?php
	}


	/**
	 * Print the tabs to switch between modules.
	 *
	 * @since 1.0
	 */
	protected function print_tabs() {
		foreach ( static::get_modules() as $key => $module ) {
			$icon   = isset( $module['icon'] ) ? $module['icon'] : 'secupress-simple';
			$class  = $this->get_current_module() === $key ? 'active' : '';
			$class .= ! empty( $module['mark_as_pro'] ) ? ' secupress-pro-module' : '';
			?>
			<li>
				<a href="<?php echo esc_url( secupress_admin_url( 'modules', $key ) ); ?>" class="<?php echo $class; ?> module-<?php echo sanitize_key( $key ); ?>">
					<span class="secupress-tab-name"><?php echo $module['title']; ?></span>
					<span class="secupress-tab-summary"><?php echo $module['summaries']['small']; ?></span>
					<i class="secupress-icon-<?php echo $icon; ?>" aria-hidden="true"></i>
				</a>
			</li>
			<?php
		}
	}


	/**
	 * Print the opening form tag.
	 *
	 * @since 1.0
	 */
	final public function print_open_form_tag() {
		?>
		<form id="secupress-module-form-settings" method="post" action="<?php echo $this->get_form_action(); ?>" enctype="multipart/form-data">
		<?php
	}


	/**
	 * Print the closing form tag and the hidden settings fields.
	 *
	 * @since 1.0
	 */
	final public function print_close_form_tag() {
		settings_fields( 'secupress_' . $this->get_current_module() . '_settings' );
		echo '</form>';
	}


	/**
	 * Print the current module.
	 *
	 * @since 1.0
	 */
	protected function print_current_module() {
		?>
		<div class="secupress-tab-content-header">
			<?php
			$this->print_module_title();
			?>
		</div>

		<?php
		if ( $this->get_with_form() ) {
			$this->print_open_form_tag();
		}
		?>

		<div class="secupress-module-options-block" id="block-advanced_options" data-module="<?php echo $this->get_current_module(); ?>">
			<?php
			$this->load_module_settings();
			$this->print_module_reset_box();
			?>
		</div>

		<?php
		if ( $this->get_with_form() ) {
			$this->print_close_form_tag();
		}
	}


	/**
	 * Print a box allowing to reset the current module settings.
	 *
	 * @since 1.0
	 */
	protected function print_module_reset_box() {
		if ( ! $this->display_module_reset_box() ) {
			return;
		}
		// //// Todo save settings with history.
		$this->set_current_section( 'reset' );
		$this->set_section_description( __( 'When you need to reset this module\'s settings to the default.', 'secupress' ) );
		$this->add_section( __( 'Module settings', 'secupress' ), array( 'with_save_button' => false ) );

		$this->set_current_plugin( 'reset' );

		$this->add_field( array(
			'title'      => __( 'Reset settings?', 'secupress' ),
			'name'       => 'reset',
			'field_type' => 'field_button',
			'url'        => wp_nonce_url( admin_url( 'admin-post.php?action=secupress_reset_settings&module=' . $this->get_current_module() ), 'secupress_reset_' . $this->get_current_module() ),
			'label'      => sprintf( __( 'Reset the %s\'s settings.', 'secupress' ), $this->get_module_title() ),
		) );

		$this->do_sections();
	}


	/**
	 * Print the module title.
	 *
	 * @since 1.0
	 *
	 * @param (string) $tag The title tag to use.
	 *
	 * @return (object) The class instance.
	 */
	protected function print_module_title( $tag = 'h2' ) {
		echo "<$tag class=\"secupress-tc-title\">";
			$this->print_module_icon();
			echo $this->get_module_title();
		echo "</$tag>\n";
		return $this;
	}


	/**
	 * Print the module descriptions.
	 *
	 * @since 1.0
	 *
	 * @return (object) The class instance.
	 */
	protected function print_module_description() {
		if ( $this->get_module_descriptions() ) {
			echo '<p>' . implode( "</p>\n<p>", $this->get_module_descriptions() ) . "</p>\n";
		}
		return $this;
	}


	/**
	 * Print the module icon.
	 *
	 * @since 1.0
	 * @author Geoffrey
	 *
	 * @return (object) The class instance.
	 */
	protected function print_module_icon() {
		if ( $this->get_module_icon() ) {
			echo '<i class="secupress-icon-' . $this->get_module_icon() . '" aria-hidden="true"></i>' . "\n";
		}
		return $this;
	}


	/** Specific fields ========================================================================= */

	/**
	 * Non login time slot field.
	 * The field is hidden in the free version.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function countries( $args ) {}


	/**
	 * Non login time slot field.
	 * The field is hidden in the free version.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function non_login_time_slot( $args ) {}


	/**
	 * Displays the scheduled backups.
	 *
	 * @since 1.0
	 */
	protected function scheduled_backups() {
		echo '<a href="' . esc_url( secupress_admin_url( 'get-pro' ) ) . '" class="secupress-button secupress-ghost secupress-button-tertiary">' . __( 'Learn more about SecuPress Pro', 'secupress' ) . '</a>';
			_e( 'This feature is available in SecuPress Pro', 'secupress' );
	}


	/**
	 * Displays the scheduled scan.
	 *
	 * @since 1.0
	 */
	protected function scheduled_scan() {
		echo '<a href="' . esc_url( secupress_admin_url( 'get-pro' ) ) . '" class="secupress-button secupress-ghost secupress-button-tertiary">' . __( 'Learn more about SecuPress Pro', 'secupress' ) . '</a>';
			_e( 'This feature is available in SecuPress Pro', 'secupress' );
	}


	/**
	 * Displays the scheduled file monitoring.
	 *
	 * @since 1.0
	 */
	protected function scheduled_monitoring() {
		echo '<a href="' . esc_url( secupress_admin_url( 'get-pro' ) ) . '" class="secupress-button secupress-ghost secupress-button-tertiary">' . __( 'Learn more about SecuPress Pro', 'secupress' ) . '</a>';
			_e( 'This feature is available in SecuPress Pro', 'secupress' );
	}


	/**
	 * Displays the banned IPs and add actions to delete them or add new ones.
	 *
	 * @since 1.0
	 */
	protected function banned_ips() {
		$ban_ips            = get_site_option( SECUPRESS_BAN_IP );
		$ban_ips            = is_array( $ban_ips ) ? $ban_ips : array();
		$offset             = get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;
		$in_ten_years       = time() + YEAR_IN_SECONDS * 10;
		$page_url           = secupress_admin_url( 'modules', 'logs' );
		$referer_arg        = '&_wp_http_referer=' . urlencode( esc_url_raw( $page_url ) );
		$is_search          = false;
		$search_val         = '';
		$empty_list_message = __( 'No banned IPs yet.', 'secupress' );

		// Ban form.
		echo '<form id="form-ban-ip" class="hide-if-js" action="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress-ban-ip' . $referer_arg ), 'secupress-ban-ip' ) ) . '" method="post">';
			echo '<label for="secupress-ban-ip" class="screen-reader-text">' . __( 'Specify an IP to ban.', 'secupress' ) . '</label><br/>';
			echo '<input type="text" id="secupress-ban-ip" name="ip" value=""/> ';
			echo '<button type="submit" class="secupress-button secupress-button-mini">' . __( 'Ban IP', 'secupress' ) . '</button>';
		echo "</form>\n";

		// Search.
		if ( $ban_ips && ! empty( $_POST['secupress-search-banned-ip'] ) ) { // WPCS: CSRF ok.
			$search    = urldecode( trim( $_POST['secupress-search-banned-ip'] ) ); // WPCS: CSRF ok.
			$is_search = true;

			if ( secupress_ip_is_valid( $search ) ) {
				$search_val = esc_attr( $search );

				if ( isset( $ban_ips[ $search ] ) ) {
					$ban_ips = array(
						$search => $ban_ips[ $search ],
					);
				} else {
					$ban_ips            = array();
					$empty_list_message = __( 'IP not found.', 'secupress' );
				}
			} else {
				$ban_ips            = array();
				$empty_list_message = __( 'Not a valid IP.', 'secupress' );
			}
		}

		// Search form.
		echo '<form id="form-search-ip"' . ( $ban_ips || $is_search ? '' : ' class="hidden"' ) . ' method="post">';
			echo '<label for="secupress-search-banned-ip" class="screen-reader-text">' . __( 'Search IP', 'secupress' ) . '</label><br/>';
			echo '<input type="search" id="secupress-search-banned-ip" name="secupress-search-banned-ip" value="' . $search_val . '"/> ';
			echo '<button type="submit" class="secupress-button secupress-button-primary" data-loading-i18n="' . esc_attr__( 'Searching...', 'secupress' ) . '" data-original-i18n="' . esc_attr__( 'Search IP', 'secupress' ) . '">' . __( 'Search IP', 'secupress' ) . '</button> ';
			echo '<span class="spinner secupress-inline-spinner hide-if-no-js"></span>';
			echo '<a class="secupress-button secupress-button-secondary' . ( $search_val ? '' : ' hidden' ) . '" id="reset-banned-ips-list" href="' . esc_url( $page_url ) . '" data-loading-i18n="' . esc_attr__( 'Reseting...', 'secupress' ) . '" data-original-i18n="' . esc_attr__( 'Reset', 'secupress' ) . '">' . __( 'Reset', 'secupress' ) . '</a> ';
			echo '<span class="spinner secupress-inline-spinner' . ( $search_val ? ' hide-if-no-js' : ' hidden' ) . '"></span>';
		echo "</form>\n";

		// Slice the list a bit: limit to 100 last results.
		if ( count( $ban_ips ) > 100 ) {
			$ban_ips = array_slice( $ban_ips, -100 );
			/** Translators: %d is 100 */
			echo '<p>' . sprintf( __( 'Last %d banned IPs:', 'secupress' ), 100 ) . "</p>\n";
		}

		// Display the list.
		echo '<ul id="secupress-banned-ips-list" class="secupress-boxed-group">';
		if ( $ban_ips ) {
			foreach ( $ban_ips as $ip => $time ) {
				echo '<li class="secupress-large-row">';
					$format = __( 'M jS Y', 'secupress' ) . ' ' . __( 'G:i', 'secupress' );
					$time   = $time > $in_ten_years ? __( 'Forever', 'secupress' ) : date_i18n( $format, $time + $offset );
					$href   = wp_nonce_url( admin_url( 'admin-post.php?action=secupress-unban-ip&ip=' . esc_attr( $ip ) . $referer_arg ), 'secupress-unban-ip_' . $ip );

					printf( '<strong>%s</strong> <em>(%s)</em>', esc_html( $ip ), $time );
					printf( '<span><a class="a-unban-ip" href="%s">%s</a> <span class="spinner secupress-inline-spinner hide-if-no-js"></span></span>', esc_url( $href ), __( 'Delete', 'secupress' ) );
				echo "</li>\n";
			}
		} else {
			echo '<li id="no-ips">' . $empty_list_message . '</li>';
		}
		echo "</ul>\n";

		// Actions.
		echo '<p id="secupress-banned-ips-actions">';
			// Display a button to unban all IPs.
			$clear_href = wp_nonce_url( admin_url( 'admin-post.php?action=secupress-clear-ips' . $referer_arg ), 'secupress-clear-ips' );
			echo '<a class="secupress-button secupress-button-secondary' . ( $ban_ips || $is_search ? '' : ' hidden' ) . '" id="secupress-clear-ips-button" href="' . esc_url( $clear_href ) . '" data-loading-i18n="' . esc_attr__( 'Clearing...', 'secupress' ) . '" data-original-i18n="' . esc_attr__( 'Clear all IPs', 'secupress' ) . '">' . __( 'Clear all IPs', 'secupress' ) . "</a>\n";
			echo '<span class="spinner secupress-inline-spinner' . ( $ban_ips || $is_search ? ' hide-if-no-js' : ' hidden' ) . '"></span>';
			// For JS: ban a IP.
			echo '<button type="button" class="secupress-button secupress-button-primary hide-if-no-js" id="secupress-ban-ip-button" data-loading-i18n="' . esc_attr__( 'Banishing...', 'secupress' ) . '" data-original-i18n="' . esc_attr__( 'Ban new IP', 'secupress' ) . '">' . __( 'Ban new IP', 'secupress' ) . "</button>\n";
			echo '<span class="spinner secupress-inline-spinner hide-if-no-js"></span>';
		echo "</p>\n";
	}


	/**
	 * Displays the textarea that lists the IP addresses not to ban.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function ips_whitelist( $args ) {
		$name_attribute = 'secupress_' . $this->modulenow . '_settings[' . $args['name'] . ']';
		$disabled       = ! empty( $args['disabled'] ) || static::is_pro_feature( $args['name'] );
		$disabled       = $disabled ? ' disabled="disabled"' : '';
		$attributes     = $disabled;
		$attributes    .= empty( $args['attributes']['cols'] ) ? ' cols="50"' : '';
		$attributes    .= empty( $args['attributes']['rows'] ) ? ' rows="5"'  : '';
		$whitelist      = secupress_get_module_option( $args['name'] );

		if ( $whitelist ) {
			$whitelist = explode( "\n", $whitelist );
			$whitelist = array_map( 'secupress_ip_is_valid', $whitelist );
			$whitelist = array_filter( $whitelist );
			natsort( $whitelist );
			$whitelist = implode( "\n", $whitelist );
		} else {
			$whitelist = '';
		}

		// Labels.
		$label_open  = '';
		$label_close = '';
		if ( '' !== $args['label_before'] || '' !== $args['label'] || '' !== $args['label_after'] ) {
			$label_open  = '<label' . ( $disabled ? ' class="disabled"' : '' ) . '>';
			$label_close = '</label>';
		}

		$this->print_open_form_tag();

			echo $label_open;
				echo $args['label'] ? $args['label'] . '<br/>' : '';
				echo $args['label_before'];
				echo '<textarea id="' . $args['label_for'] . '" name="' . $name_attribute . '"' . $attributes . '>' . esc_textarea( $whitelist ) . "</textarea>\n";
				echo $args['label_after'];
			echo $label_close;

			echo '<p class="description">' . __( 'One IP address per line.', 'secupress' ) . "</p>\n";

			echo '<p class="submit"><button type="submit" class="secupress-button secupress-button-primary"' . $disabled . '> ' . __( 'Save whitelist', 'secupress' ) . '</button></p>';

		$this->print_close_form_tag();
	}


	/**
	 * Displays the checkbox to activate the "action" Logs.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function activate_action_logs( $args ) {
		$name_attribute = 'secupress-plugin-activation[' . $args['name'] . ']';
		$disabled       = ! empty( $args['disabled'] ) || static::is_pro_feature( $args['name'] );
		$disabled       = $disabled ? ' disabled="disabled"' : '';
		$value          = (int) secupress_is_submodule_active( 'logs', 'action-logs' );

		// Labels.
		$label_open  = '';
		$label_close = '';
		if ( '' !== $args['label_before'] || '' !== $args['label'] || '' !== $args['label_after'] ) {
			$label_open  = '<label' . ( $disabled ? ' class="disabled"' : '' ) . '>';
			$label_close = '</label>';
		}
		?>
		<form action="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_activate_action_logs' ), 'secupress_activate_action_logs' ) ); ?>" id="form-activate-action-logs" method="post">
			<p>
				<?php
				echo $label_open;
				echo $args['label_before'];
				echo ' <input type="checkbox" id="' . $args['label_for'] . '" name="' . $name_attribute . '" value="1"' . checked( $value, 1, false ) . $disabled . ' class="secupress-checkbox" /> ';
				echo '<span class="label-text">' . $args['label'] . '</span>';
				echo $label_close;
				?>
			</p>
			<p class="description desc">
				<?php _e( 'Post creation or update will not be logged, but rather password and profile update, email changes, new administrator user, admin has logged in...', 'secupress' ); ?>
			</p>
			<p class="submit"><button type="submit" class="secupress-button secupress-button-primary"><?php _e( 'Submit' ); ?></button></p>
		</form>
		<?php
	}


	/**
	 * Displays the checkbox to activate the "404" Logs.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function activate_404_logs( $args ) {
		$name_attribute = 'secupress-plugin-activation[' . $args['name'] . ']';
		$disabled       = ! empty( $args['disabled'] ) || static::is_pro_feature( $args['name'] );
		$disabled       = $disabled ? ' disabled="disabled"' : '';
		$value          = (int) secupress_is_submodule_active( 'logs', '404-logs' );

		// Labels.
		$label_open  = '';
		$label_close = '';
		if ( '' !== $args['label_before'] || '' !== $args['label'] || '' !== $args['label_after'] ) {
			$label_open  = '<label' . ( $disabled ? ' class="disabled"' : '' ) . '>';
			$label_close = '</label>';
		}
		?>
		<form action="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_activate_404_logs' ), 'secupress_activate_404_logs' ) ); ?>" id="form-activate-404-logs" method="post">
			<p><?php echo $label_open; ?>
				<?php
				echo $args['label_before'];
				echo ' <input type="checkbox" id="' . $args['label_for'] . '" name="' . $name_attribute . '" value="1"' . checked( $value, 1, false ) . $disabled . 'class="secupress-checkbox" /> ';
				echo '<span class="label-text">' . $args['label'] . '</span>';
				?>
			<?php echo $label_close; ?>
			</p>
			<?php echo '<p class="submit"><button type="submit" class="secupress-button secupress-button-primary">' . __( 'Submit' ) . '</button></p>'; ?>
		</form>
		<?php
	}


	/**
	 * Displays the old backups.
	 *
	 * @since 1.0
	 */
	protected function backup_history() {
		?>
		<p id="secupress-no-backups"><em><?php _e( 'No backups found yet, run one now?', 'secupress' ); ?></em></p>
		<?php
	}


	/**
	 * Displays the tables to launch a backup
	 *
	 * @since 1.0
	 */
	protected function backup_db() {
		?>
		<p class="submit">
			<button type="button" disabled="disabled" class="secupress-button">
				<span class="icon">
					<i class="secupress-icon-download"></i>
				</span>
				<span class="text">
					<?php esc_html_e( 'Backup my database', 'secupress' ); ?>
				</span>
			</button>
		</p>
		<?php
	}


	/**
	 * Displays the files backups and the button to launch one.
	 *
	 * @since 1.0
	 */
	protected function backup_files() {
		?>
		<p class="submit">
			<button type="button" disabled="disabled" class="secupress-button">
				<span class="icon">
					<i class="secupress-icon-download"></i>
				</span>
				<span class="text">
					<?php esc_html_e( 'Backup my files', 'secupress' ); ?>
				</span>
			</button>
		</p>
		<?php
	}


	/**
	 * Scan the installation and search for modified/malicious files
	 *
	 * @since 1.0
	 */
	protected function file_scanner() {
		?>
		<p class="submit">
			<button type="button" disabled="disabled" class="secupress-button">
				<?php _e( 'Search for malicious files', 'secupress' ); ?>
			</button>
		</p>
		<?php
	}


	/** Includes ================================================================================ */

	/**
	 * Include the current module settings file.
	 *
	 * @since 1.0
	 *
	 * @return (object) The class instance.
	 */
	final protected function load_module_settings() {
		$module_file = SECUPRESS_MODULES_PATH . $this->modulenow . '/settings.php';

		if ( file_exists( $module_file ) ) {
			require_once( $module_file );
		}

		return $this;
	}


	/**
	 * Include a plugin settings file. Also, automatically set the current module and print the sections.
	 *
	 * @since 1.0
	 *
	 * @param (string) $plugin The plugin.
	 *
	 * @return (object) The class instance.
	 */
	final protected function load_plugin_settings( $plugin ) {
		/**
		 * Give the possibility to hide a full block of options
		 *
		 * @since 1.4
		 *
		 * @param (bool) false by default
		 */

		if ( false !== apply_filters( 'secupress.settings.load_plugin.' . $plugin, false ) ) {
			return;
		}
		$plugin_file = SECUPRESS_MODULES_PATH . $this->modulenow . '/settings/' . $plugin . '.php';

		return $this->require_settings_file( $plugin_file, $plugin );
	}


	/** Other =================================================================================== */

	/**
	 * Filter the arguments passed to the section submit button and disable it.
	 *
	 * @since 1.0.6
	 * @author Grégory Viguier
	 *
	 * @param (array) $args An array of arguments passed to the `submit_button()` method.
	 *
	 * @return (array)
	 */
	public function disable_sumit_buttons( $args ) {
		$wrap = isset( $args['wrap'] ) ? $args['wrap'] : true;
		$atts = array();
		$atts = isset( $args['other_attributes'] ) && is_array( $args['other_attributes'] ) ? $args['other_attributes'] : array();
		$atts = array_merge( $atts, array(
			'disabled'      => 'disabled',
			'aria-disabled' => 'true',
		) );

		return array_merge( $args, array(
			'wrap'             => $wrap,
			'other_attributes' => $atts,
		) );
	}
}
