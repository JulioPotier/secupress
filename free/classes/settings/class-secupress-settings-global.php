<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Global settings class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Settings
 * @since 1.0
 */
class SecuPress_Settings_Global extends SecuPress_Settings {

	const VERSION = '1.1';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Setters ================================================================================= */

	/**
	 * Set the current module.
	 *
	 * @since 1.0
	 * @author Grégory Viguier
	 *
	 * @return (object) The class instance.
	 */
	protected function set_current_module() {
		$this->modulenow = 'global';
		return $this;
	}


	/** Init ==================================================================================== */

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 */
	protected function _init() {
		$this->set_current_module();

		$this->form_action = esc_url( admin_url( 'admin-post.php' ) );
	}


	/** Main template tags ====================================================================== */

	/**
	 * Print the page content.
	 *
	 * @since 1.0
	 * @author Grégory Viguier
	 */
	public function print_page() {

		$setting_modules = array( 'settings-manager' );
		if ( ! secupress_is_white_label() && ( ! defined( 'SECUPRESS_HIDE_API_KEY' ) || ! SECUPRESS_HIDE_API_KEY ) ) {
			$setting_modules = array( 'api-key', 'settings-manager' );
		}

		/**
		 * Filter the modules of the global settings.
		 *
		 * @since 1.0
		 *
		 * @param (array) $setting_modules The modules.
		 */
		$setting_modules = apply_filters( 'secupress.global_settings.modules', $setting_modules );
		$secupress_has_sideads = apply_filters( 'secupress.no_sidebar', true ) && apply_filters( 'secupress.no_sideads', true );
		?>
		<div class="wrap">

			<div class="secupress-setting-wrapper<?php echo ( $secupress_has_sideads ? ' secupress-has-sideads' : '' ) ?>">

				<div class="secupress-setting-content">
					<?php
					secupress_admin_heading( __( 'Settings' ) );
					settings_errors();
					secupress_settings_heading( array(
						'title'    => esc_html__( 'Settings', 'secupress' ),
						'subtitle' => esc_html__( 'Overall plugin settings and fine-tuning', 'secupress' ),
					) );
					?>
					<div class="secupress-section-light secupress-bordered">

							<?php array_map( array( $this, 'load_module_settings' ), $setting_modules ); ?>

					</div>
				</div>

				<?php $this->print_sideads(); ?>

			</div><!-- .secupress-setting-content -->
		</div><!-- .wrap -->
		<?php
	}


	/**
	 * Print the opening form tag.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @param (string) $module A setting module name.
	 */
	final public function print_open_form_tag( $module ) {
		?>
		<form id="secupress-module-form-global-<?php echo $module; ?>" method="post" action="<?php echo $this->get_form_action(); ?>" enctype="multipart/form-data">
		<?php
	}


	/**
	 * Print the closing form tag and the hidden settings fields.
	 *
	 * @since 1.1.4
	 * @author Grégory Viguier
	 *
	 * @param (string) $module A setting module name.
	 */
	final public function print_close_form_tag( $module ) {
		$module = 'secupress_update_global_settings_' . $module;
		echo '<input type="hidden" name="action" value="' . $module . '" />';
		echo '<input type="hidden" id="' . $module . '-nonce" name="_wpnonce" value="' . wp_create_nonce( $module ) . '" />';
		wp_referer_field();
		echo '</form>';
	}


	/** Includes ================================================================================ */

	/**
	 * Include a module settings file. Also, automatically set the current module and print the sections.
	 *
	 * @since 1.0
	 * @author Grégory Viguier
	 *
	 * @param (string) $module The module.
	 *
	 * @return (object) The class instance.
	 */
	protected function load_module_settings( $module ) {
		$module_file = SECUPRESS_ADMIN_SETTINGS_MODULES . $module . '.php';

		$this->print_open_form_tag( $module );
		$this->require_settings_file( $module_file, $module );
		$this->print_close_form_tag( $module );

		return $this;
	}
}
