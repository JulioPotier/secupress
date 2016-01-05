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

	protected static $modules;

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;


	// Setters =====================================================================================

	final protected static function set_modules() {
		static::$modules = secupress_get_modules();
	}


	final protected function set_current_module() {
		$this->modulenow = isset( $_GET['module'] ) ? $_GET['module'] : 'welcome';
		$this->modulenow = array_key_exists( $this->modulenow, static::get_modules() ) && file_exists( SECUPRESS_MODULES_PATH . $this->modulenow . '/settings.php' ) ? $this->modulenow : 'welcome';
		return $this;
	}


	// Getters =====================================================================================

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
	 * @param (string) $module : the desired module.
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
	 * @param (string) $module : the desired module.
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
	 * Tell if the reset box should be displayed for a specific module.
	 *
	 * @since 1.0
	 *
	 * @param (string) $module : the desired module.
	*/
	final public function display_module_reset_box( $module = false ) {
		$modules = static::get_modules();
		$module  = $module ? $module : $this->modulenow;

		return isset( $modules[ $module ]['with_reset_box'] ) ? (bool) $modules[ $module ]['with_reset_box'] : false;
	}


	// Main template tags ==========================================================================

	public function print_page() {
		?>
		<div class="wrap">
			<?php secupress_admin_heading( __( 'Modules', 'secupress' ) ); ?>
			<?php settings_errors(); ?>

			<div class="secupress-wrapper">

				<h2 class="nav-tab-wrapper hide-if-no-js">
					<?php $this->print_tabs(); ?>
				</h2>

				<div id="tab_content">
					<?php $this->print_current_module(); ?>
				</div>

			</div>

		</div>
		<?php
	}


	protected function print_tabs() {
		foreach ( static::get_modules() as $key => $module ) {
			$class = $this->get_current_module() === $key  ? ' nav-tab-active'    : '';
			$icon  = isset( $module['dashicon'] )          ?  $module['dashicon'] : 'admin-generic';
			?>
			<a href="<?php echo secupress_admin_url( 'modules', $key ); ?>" class="nav-tab<?php echo $class; ?> active_module">
				<span class="dashicons dashicons-<?php echo $icon; ?>" aria-hidden="true"></span> <?php echo $module['title']; ?>
			</a>
			<?php
		}
	}


	protected function print_current_module() {

		// No module.
		if ( 'welcome' === $this->get_current_module() ) {
			?>
			<div class="secublock">
				<?php $this->load_module_settings(); ?>
			</div>
			<?php
			return;
		}

		?>
		<div class="secublock">
			<?php
			$this->print_module_title();
			$this->print_module_description();
			?>
		</div>

		<form id="secupress-module-form-settings" method="post" action="<?php echo $this->get_form_action(); ?>">

			<div id="block-advanced_options" data-module="<?php echo $this->get_current_module(); ?>">
				<?php
				$this->load_module_settings();
				$this->print_module_reset_box();
				?>
			</div>

			<?php settings_fields( 'secupress_' . $this->get_current_module() . '_settings' ); ?>

		</form>
		<?php
	}


	protected function print_module_reset_box() {
		if ( ! $this->display_module_reset_box() ) {
			return;
		}
		//// todo save settings with history
		$this->set_current_section( 'reset' );
		$this->set_section_description( __( 'If you need to reset this module\'s settings to the default ones, you just have to do it here, we will set the best for your site.', 'secupress' ) );
		$this->add_section( __( 'Module settings', 'secupress' ), array( 'with_save_button' => false, ) );

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


	protected function print_module_title( $tag = 'h3' ) {
		echo "<$tag>" . $this->get_module_title() . "</$tag>\n";
		return $this;
	}


	protected function print_module_description() {
		if ( $this->get_module_descriptions() ) {
			echo '<p>' . implode( "</p>\n<p>", $this->get_module_descriptions() ) . "</p>\n";
		}
		return $this;
	}


	// Includes ====================================================================================

	final protected function load_module_settings() {
		$module_file = SECUPRESS_MODULES_PATH . $this->modulenow . '/settings.php';

		if ( file_exists( $module_file ) ) {
			require( $module_file );
		}

		return $this;
	}


	// secupress_load_settings()
	final protected function load_plugin_settings( $plugin ) {
		$plugin_file = SECUPRESS_MODULES_PATH . $this->modulenow . '/settings/' . $plugin . '.php';

		return $this->require_settings_file( $plugin_file, $plugin );
	}
}
