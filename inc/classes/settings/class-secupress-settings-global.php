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
		$setting_modules = array( 'api-key', 'settings-manager' );

		/**
		 * Filter the modules of the global settings.
		 *
		 * @since 1.0
		 *
		 * @param (array) $setting_modules The modules.
		 */
		$setting_modules = apply_filters( 'secupress.global_settings.modules', $setting_modules );
		?>
		<div class="wrap">

			<div class="secupress-setting-wrapper<?php echo ( ! secupress_is_pro() ? ' secupress-has-sideads' : '' ) ?>">

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


	/** Specific fields ========================================================================= */

	/**
	 * Outputs the form used by the importers to accept the data to be imported.
	 *
	 * @since 1.0
	 * @author Julio Potier
	 */
	protected function import_upload_form() {
		/** This filter is documented in wp-admin/includes/template.php */
		$bytes      = apply_filters( 'import_upload_size_limit', wp_max_upload_size() );
		$size       = size_format( $bytes );
		$upload_dir = wp_upload_dir();
		$disabled   = secupress_is_pro() ? '' : ' disabled="disabled"';

		if ( ! empty( $upload_dir['error'] ) ) {
			?>
			<div class="error">
				<p><?php _e( 'Before you can upload your import file, you will need to fix the following error:', 'secupress' ); ?></p>
				<p><strong><?php echo $upload_dir['error']; ?></strong></p>
			</div><?php
			echo secupress_is_pro() ? '' : static::get_pro_version_string( '<p class="description secupress-get-pro-version">%s</p>' );
			return;
		}

		$name        = 'upload';
		$type        = 'help';
		$description = __( 'Choose a file from your computer:', 'secupress' ) . ' (' . sprintf( __( 'Maximum size: %s', 'secupress' ), $size ) . ')';
		/** This filter is documented in inc/classes/settings/class-secupress-settings.php */
		$description = apply_filters( 'secupress.settings.help', $description, $name, $type );
		?>
		<p>
			<input type="file" id="upload" name="import" size="25"<?php echo $disabled; ?>/><br/>
			<label for="upload"><?php echo $description; ?></label>
			<input type="hidden" name="max_file_size" value="<?php echo $bytes; ?>" />
		</p>

		<p class="submit">
			<button type="submit"<?php echo $disabled; ?> class="secupress-button" id="import">
				<span class="icon">
					<i class="secupress-icon-upload" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php _e( 'Upload file and import settings', 'secupress' ); ?>
				</span>
			</button>
		</p>
		<?php
		echo secupress_is_pro() ? '' : static::get_pro_version_string( '<p class="description secupress-get-pro-version">%s</p>' );
	}


	/**
	 * Outputs the export button.
	 *
	 * @since 1.0
	 * @author Julio Potier
	 */
	protected function export_form() {
		?>
		<p class="submit">
			<?php if ( secupress_is_pro() ) : ?>
				<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export' ), 'secupress_export' ) ); ?>" id="export" class="secupress-button">
					<span class="icon" aria-hidden="true">
						<i class="secupress-icon-download"></i>
					</span>
					<span class="text">
						<?php _e( 'Download settings', 'secupress' ); ?>
					</span>
				</a>
			<?php else : ?>
				<button type="button" class="secupress-button" disabled="disabled">
					<span class="icon" aria-hidden="true">
						<i class="secupress-icon-download"></i>
					</span>
					<span class="text">
						<?php _e( 'Download settings', 'secupress' ); ?>
					</span>
				</button>
			<?php endif; ?>
		</p>
		<?php
		echo secupress_is_pro() ? '' : static::get_pro_version_string( '<p class="description secupress-get-pro-version">%s</p>' );
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
