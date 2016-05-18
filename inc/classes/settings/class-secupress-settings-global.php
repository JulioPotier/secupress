<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Global settings class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Settings
 * @since 1.0
 */
class SecuPress_Settings_Global extends SecuPress_Settings {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	// Setters =====================================================================================.

	/**
	 * Set the current module.
	 *
	 * @since 1.0
	 *
	 * @return (object) The class instance.
	 */
	protected function set_current_module() {
		$this->modulenow = 'global';
		return $this;
	}


	// Main template tags ==========================================================================.

	/**
	 * Print the page content.
	 *
	 * @since 1.0
	 */
	public function print_page() {
		$setting_modules = array(
			'api-key',
			'settings-manager',
		);

		/**
		 * Filter the modules of the global settings.
		 *
		 * @since 1.0
		 *
		 * @param (array) $setting_modules The modules.
		 */
		$setting_modules = apply_filters( 'secupress.global_settings.modules', $setting_modules );
		?>
		<div class="wrap secupress-setting-wrapper">
			<?php secupress_admin_heading( __( 'Settings' ) ); ?>
			<?php settings_errors(); ?>
			<?php
				$titles = array(
					'title'    => esc_html__( 'Settings', 'secupress' ),
					'subtitle' => esc_html__( 'Overall plugin settings and fine tuning', 'secupress' )
				);
				secupress_settings_heading( $titles );
			?>
			<div class="secupress-section-light">

				<form action="<?php echo $this->get_form_action(); ?>" method="post" id="secupress_settings">

					<?php array_map( array( $this, 'load_module_settings' ), $setting_modules ); ?>

					<?php settings_fields( 'secupress_global_settings' ); ?>

				</form>

			</div>

		</div>
		<?php
	}


	// Includes ====================================================================================.

	/**
	 * Include a module settings file. Also, automatically set the current module and print the sections.
	 *
	 * @since 1.0
	 *
	 * @param (string) $module The module.
	 *
	 * @return (object) The class instance.
	 */
	protected function load_module_settings( $module ) {
		$module_file = SECUPRESS_ADMIN_SETTINGS_MODULES . $module . '.php';

		return $this->require_settings_file( $module_file, $module );
	}
}
