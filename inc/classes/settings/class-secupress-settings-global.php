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
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;


	// Setters =====================================================================================

	protected function set_current_module() {
		$this->modulenow = 'global';
		return $this;
	}


	// Main template tags ==========================================================================

	public function print_page() {
		$setting_modules = array(
			'api-key',
			'auto-config',
		);
		$setting_modules = apply_filters( 'secupress_global_settings_modules', $setting_modules );
		?>
		<div class="wrap">
			<?php secupress_admin_heading( __( 'Settings' ) ); ?>
			<?php settings_errors(); ?>

			<form action="options.php" method="post" id="secupress_settings" class="secupress-wrapper">

				<?php array_map( array( $this, 'load_module_settings'), $setting_modules ); ?>

				<div class="secublock">
					<h2><?php _e( 'That\'s all!', 'secupress' ); ?></h2>
					<p><?php printf( __( 'Looking for more settings? Each other setting is included in its own module, just <a href="%s">check them</a> if you need.', 'secupress' ), esc_url( secupress_admin_url( 'secupress' ) ) ); ?></p>
				</div>

				<?php settings_fields( 'secupress_global_settings' ); ?>

			</form>

		</div>
		<?php
	}


	// Includes ====================================================================================

	final protected function load_module_settings( $module ) {
		$module_file = SECUPRESS_ADMIN_SETTINGS_MODULES . $module . '.php';

		return $this->require_settings_file( $module_file, $module );
	}
}
