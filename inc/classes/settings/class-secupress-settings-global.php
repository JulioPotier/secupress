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
		// 'api-key',////.
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
					'subtitle' => esc_html__( 'Overall plugin settings and fine-tuning', 'secupress' ),
				);
				secupress_settings_heading( $titles );
			?>
			<div class="secupress-section-light secupress-bordered">

				<form action="<?php echo $this->get_form_action(); ?>" method="post" id="secupress_settings">

					<?php array_map( array( $this, 'load_module_settings' ), $setting_modules ); ?>

					<?php settings_fields( 'secupress_global_settings' ); ?>

				</form>

			</div>

		</div>
		<?php
	}


	// Specific fields =============================================================================.

	/**
	 * Outputs the form used by the importers to accept the data to be imported.
	 *
	 * @since 1.0
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
					<i class="icon-upload" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php esc_html_e( 'Upload file and import settings', 'secupress' ); ?>
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
	 */
	protected function export_form() {
		?>
		<p class="submit">
			<?php if ( secupress_is_pro() ) : ?>
				<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export' ), 'secupress_export' ) ); ?>" id="export" class="secupress-button">
					<span class="icon" aria-hidden="true">
						<i class="icon-download"></i>
					</span>
					<span class="text">
						<?php _e( 'Download settings', 'secupress' ); ?>
					</span>
				</a>
			<?php else : ?>
				<button type="button" class="secupress-button" disabled="disabled">
					<span class="icon" aria-hidden="true">
						<i class="icon-download"></i>
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
