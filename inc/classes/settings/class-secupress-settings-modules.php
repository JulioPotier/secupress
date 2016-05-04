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


	// Setters =====================================================================================.

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


	// Getters =====================================================================================.

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

		return isset( $modules[ $module ]['with_reset_box'] ) ? (bool) $modules[ $module ]['with_reset_box'] : false;
	}


	// Init ========================================================================================.

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		parent::_init();

		$modules = static::get_modules();

		$this->with_form = ! ( isset( $modules[ $this->modulenow ]['with_form'] ) && false === $modules[ $this->modulenow ]['with_form'] );
	}


	// Main template tags ==========================================================================.

	/**
	 * Print the page content.
	 *
	 * @since 1.0
	 */
	public function print_page() {
		$is_welcome = 'welcome' !== $this->get_current_module() ? false : true;
		?>
		<div class="wrap">

			<?php secupress_admin_heading( __( 'Modules', 'secupress' ) ); ?>
			<?php settings_errors(); ?>

			<div class="secupress-wrapper<?php echo ( $is_welcome ? '' : ' secupress-flex secupress-flex-top' ) ?>">

				<?php
				/**
				 * Don't print sidebar if we are in Welcome page.
				 * Modules are included in the content of the page.
				 */
				if ( ! $is_welcome ) {
					$type         = true ? 'free' : 'pro';
					$suffix       = 'free' === $type ? '' : '-pro';
					$version_free = sprintf( esc_html__( 'Free version %s', 'secupress' ), 'v' . SECUPRESS_VERSION );
					$version_pro  = sprintf( esc_html__( 'Pro version %s', 'secupress' ), 'v' . SECUPRESS_VERSION ); // ////.
					?>
					<div class="secupress-modules-sidebar hide-if-no-js">
						<div class="secupress-sidebar-header">
							<div class="secupress-flex">
								<div class="secupress-sh-logo">
									<img src="<?php echo SECUPRESS_ADMIN_IMAGES_URL; ?>logo<?php echo $suffix; ?>.png" srcset="<?php echo SECUPRESS_ADMIN_IMAGES_URL; ?>logo<?php echo $suffix; ?>2x.svg 1x, <?php echo SECUPRESS_ADMIN_IMAGES_URL; ?>logo<?php echo $suffix; ?>2x.svg 2x" alt="">
								</div>
								<div class="secupress-sh-name">
									<p class="secupress-sh-title">SecuPress</p>
									<p class="secupress-sh-subtitle"><?php esc_html_e( 'the best security for WordPress', 'secupress' ); ?></p>
								</div>
							</div>
						</div>

						<ul id="secupress-modules-navigation" class="secupress-modules-list-links">
							<?php $this->print_tabs(); ?>
						</ul>
					</div>
					<?php
				} ?>

				<div class="secupress-tab-content secupress-tab-content-<?php echo $this->get_current_module(); ?>" id="secupress-tab-content">
					<?php $this->print_current_module(); ?>
				</div>

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
			$class = $this->get_current_module() === $key  ? ' active'    : '';
			$icon  = isset( $module['dashicon'] )          ?  $module['dashicon'] : 'admin-generic';
			?>
			<li>
				<a href="<?php echo esc_url( secupress_admin_url( 'modules', $key ) ); ?>" class="<?php echo $class; ?> module-<?php echo sanitize_key( $key ); ?>">
					<span class="secupress-tab-name"><?php echo $module['title']; ?></span>
					<span class="secupress-tab-summary"><?php echo $module['summaries']['small']; ?></span>
					<i class="dashicons dashicons-<?php echo $icon; ?>" aria-hidden="true"></i>
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
		if ( $this->get_with_form() ) {
			?>
			<form id="secupress-module-form-settings" method="post" action="<?php echo $this->get_form_action(); ?>">
			<?php
		}
	}


	/**
	 * Print the closing form tag and the hidden settings fields.
	 *
	 * @since 1.0
	 */
	final public function print_close_form_tag() {
		if ( $this->get_with_form() ) {
			settings_fields( 'secupress_' . $this->get_current_module() . '_settings' );
			echo '</form>';
		}
	}


	/**
	 * Print the current module.
	 *
	 * @since 1.0
	 */
	protected function print_current_module() {
		// No module.
		if ( 'welcome' === $this->get_current_module() ) {
			$this->load_module_settings();
			return;
		}
		?>

		<div class="secupress-tab-content-header">
			<?php
			$this->print_module_title();
			$this->print_module_description();
			?>
		</div>

		<?php $this->print_open_form_tag(); ?>

		<div class="secupress-module-options-block" id="block-advanced_options" data-module="<?php echo $this->get_current_module(); ?>">
			<?php
			$this->load_module_settings();
			$this->print_module_reset_box();
			?>
		</div>

		<?php
		$this->print_close_form_tag();
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
		$this->set_section_description( __( 'If you need to reset this module\'s settings to the default ones, you just have to do it here, we will set the best for your site.', 'secupress' ) );
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
		echo '<' . $tag . ' class="secupress-tc-title">' . $this->get_module_title() . "</$tag>\n";
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


	// Includes ====================================================================================.

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
			require( $module_file );
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
		$plugin_file = SECUPRESS_MODULES_PATH . $this->modulenow . '/settings/' . $plugin . '.php';

		return $this->require_settings_file( $plugin_file, $plugin );
	}
}
