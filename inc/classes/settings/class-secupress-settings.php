<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');


/**
 * Base class for settings.
 *
 * @package SecuPress
 * @since 1.0
 */

abstract class SecuPress_Settings {

	const VERSION = '1.0';

	protected $modulenow;  // Tab (page), like `users_login`.
	protected $sectionnow; // Section, like `login_auth`.
	protected $pluginnow;  // Field, like `double_auth`.
	protected $sections_descriptions = array();
	protected $sections_save_button  = array();
	protected $form_action;


	// Instance ====================================================================================

	/**
	 * Returns the *Singleton* instance of this class.
	 *
	 * @return Singleton The *Singleton* instance.
	 */
	final public static function get_instance() {
		if ( ! isset( static::$_instance ) ) {
			static::$_instance = new static;
		}

		return static::$_instance;
	}


	/**
	 * Protected constructor to prevent creating a new instance of the *Singleton* via the `new` operator from outside of this class.
	 */
	final private function __construct() {
		$this->init();
	}


	/**
	 * Private clone method to prevent cloning of the instance of the *Singleton* instance.
	 *
	 * @return void
	 */
	final private function __clone() {}


	/**
	 * Private unserialize method to prevent unserializing of the *Singleton* instance.
	 *
	 * @return void
	 */
	final private function __wakeup() {}


	// Setters =====================================================================================

	protected function set_current_module() {
		die( 'Method SecuPress_Settings::set_current_module() must be over-ridden in a sub-class.' );
	}


	final protected function set_current_section( $section ) {
		$this->sectionnow = $section;
		return $this;
	}


	final protected function set_current_plugin( $plugin ) {
		$this->pluginnow = $plugin;
		return $this;
	}


	final protected function set_section_description( $description ) {
		$section_id = $this->modulenow . '|' . $this->sectionnow;

		$this->sections_descriptions[ $section_id ] = $description;

		return $this;
	}


	final protected function set_section_save_button( $value ) {
		$section_id = $this->get_section_id();

		if ( $value ) {
			$this->sections_save_button[ $section_id ] = 1;
		} else {
			unset( $this->sections_save_button[ $section_id ] );
		}

		return $this;
	}


	// Getters =====================================================================================

	final public function get_current_module() {
		return $this->modulenow;
	}


	final public function get_current_section() {
		return $this->sectionnow;
	}


	final public function get_current_plugin() {
		return $this->pluginnow;
	}


	public function get_section_id() {
		return 'module_' . $this->modulenow . '|' . $this->sectionnow;
	}


	final public function get_form_action() {
		return $this->form_action;
	}


	// Init ========================================================================================

	protected function init() {
		$this->form_action = is_network_admin() ? admin_url( 'admin-post.php' ) : admin_url( 'options.php' );
		$this->form_action = esc_url( $this->form_action );

		$this->set_current_module();
	}


	// Main template tags ==========================================================================

	public function print_page() {
		die( 'Method SecuPress_Settings::print_page() must be over-ridden in a sub-class.' );
	}


	// Sections ====================================================================================

	protected function add_section( $title, $args = null ) {
		static $i = 0;

		$args       = wp_parse_args( $args, array( 'with_roles' => false, 'with_save_button' => true ) );
		$actions    = '';
		$section_id = $this->get_section_id();

		if ( ! empty( $args['with_roles'] ) ) {
			$actions .= '<button type="button" id="affected-role-' . $i . '" class="hide-if-no-js no-button button-actions-title">' . __( 'Roles', 'secupress' ) . ' <span class="dashicons dashicons-arrow-right" aria-hidden="true"></span></button>';
		}

		do_action( 'before_section_' . $this->sectionnow );

		add_settings_section(
			$section_id,
			$title . $actions,
			array( $this, 'print_section_description' ),
			$section_id
		);

		if ( $args['with_save_button'] ) {
			$this->sections_save_button[ $section_id ] = 1;
		}

		if ( ! $args['with_roles'] ) {
			return $this;
		}

		$field_name = $this->get_field_name( 'affected_role' );

		$this->add_field(
			'<span class="dashicons dashicons-groups"></span> ' . __( 'Affected Roles', 'secupress' ),
			array(
				'description' => __( 'Which roles will be affected by this module?', 'secupress' ),
				'name'        => $field_name,
			),
			array(
				'depends'     => 'affected-role-' . $i,
				array(
					'type'         => 'roles',
					'default'      => array(), //// (TODO) not supported yet why not $args['with_roles']
					'name'         => $field_name,
					'label_for'    => $field_name,
					'label'        => '',
					'label_screen' => __( 'Affected Roles', 'secupress' ),
				),
				array(
					'type'         => 'helper_description',
					'name'         => $field_name,
					'description'  => __( 'Future roles will be automatically checked.', 'secupress' )
				),
				array(
					'type'         => 'helper_warning',
					'name'         => $field_name,
					'class'        => 'hide-if-js',
					'description'  => __( 'Select 1 role minimum', 'secupress' )
				),
			)
		);

		++$i;

		return $this;
	}

	// do_secupress_settings_sections() + secupress_do_secupress_settings_sections()
	protected function do_sections() {

		$section_id = $this->get_section_id();

		echo '<div class="secublock">';
			$this->do_settings_sections();
		echo '</div>';

		if ( ! empty( $this->sections_save_button[ $section_id ] ) ) {
			static::submit_button( 'primary small', $this->sectionnow . '_submit' );

			do_action( 'after_section_' . $this->sectionnow );
		}

		return $this;
	}


	/**
	 * Like the real `do_settings_sections()` but using a custom `do_settings_fields()`.
	 *
	 * @return void
	 */
	final protected function do_settings_sections() {
		global $wp_settings_sections, $wp_settings_fields;

		$section_id = $this->get_section_id();

		if ( ! isset( $wp_settings_sections[ $section_id ] ) ) {
			return;
		}

		foreach ( (array) $wp_settings_sections[ $section_id ] as $section ) {
			if ( $section['title'] ) {
				echo '<h3 id="' . sanitize_key( $section['title'] ) . '">' . $section['title'] . '</h3>' . "\n";
			}

			if ( $section['callback'] ) {
				call_user_func( $section['callback'], $section );
			}

			if ( ! isset( $wp_settings_fields ) || ! isset( $wp_settings_fields[ $section_id ] ) || ! isset( $wp_settings_fields[ $section_id ][ $section['id'] ] ) ) {
				continue;
			}

			echo '<table class="form-table">';
				static::do_settings_fields( $section_id, $section['id'] );
			echo '</table>';
		}
	}


	// Fields ======================================================================================

	// secupress_field()
	protected function field( $args ) {

		if ( ! is_array( end( $args ) ) ) {
			$args = array( $args );
		}

		$args = array_filter( $args, 'is_array' );

		$full = $args;

		foreach ( $full as $args ) {
			if ( isset( $args['display'] ) && ! $args['display'] ) {
				continue;
			}

			$args['label_for'] = isset( $args['label_for'] )    ? $args['label_for'] : '';
			$args['name']      = isset( $args['name'] )         ? $args['name'] : $args['label_for'];
			$option_name       = 'secupress' . ( 'global' !== $this->modulenow ? '_' . $this->modulenow : '' ) . '_settings';
			$default           = isset( $args['default'] )      ? $args['default'] : '';
			if ( isset( $args['value'] ) ) {
				$value         = $args['value'];
			} elseif ( 'global' === $this->modulenow ) {
				$value         = secupress_get_option( $args['name'] );
			} else {
				$value         = secupress_get_module_option( $args['name'] );
			}
			$value             = ! is_null( $value )            ? $value : $default;
			$parent            = isset( $args['parent'] )       ? 'data-parent="' . sanitize_html_class( $args['parent'] ). '"' : null;
			$placeholder       = isset( $args['placeholder'] )  ? 'placeholder="'. $args['placeholder'].'" ' : '';
			$label             = isset( $args['label'] )        ? $args['label'] : '';
			$required          = isset( $args['required'] )     ? ' data-required="required" data-aria-required="true"' : '';
			$pattern           = isset( $args['pattern'] )      ? ' data-pattern="' . $args['pattern'] . '"' : '';
			$title             = isset( $args['title'] )        ? ' title="' . $args['title'] . '"' : '';
			$cols              = isset( $args['cols'] )         ? (int) $args['cols'] : 50;
			$rows              = isset( $args['rows'] )         ? (int) $args['rows'] : 5;
			$size              = isset( $args['size'] )         ? (int) $args['size'] : 1;
			$readonly          = ! empty( $args['readonly'] )   ? ' readonly="readonly" disabled="disabled"' : '';
			$class             = ! empty( $args['class'] )      ? $args['class'] : '';
			$radio_style       = 'radioboxes' == $args['type'];
			$field_type        = 'radioboxes' == $args['type']  ? 'checkboxes' : $args['type'];

			// Classes
			if ( is_array( $class ) ) {
				$class = implode( ' ', array_map( 'sanitize_html_class', $class ) );
			}
			else {
				$class = sanitize_html_class( $class );
			}

			$class .= $parent ? ' has-parent' : '';
			$class  = $class ? ' ' . trim( $class ) : '';

			$depends = '';
			if ( ! empty( $args['depends'] ) ) {
				$args['depends'] = explode( ' ', $args['depends'] );
				$depends = ' depends-' . implode( ' depends-', $args['depends'] );
			}

			$has_fieldset_begin = ! isset( $args['fieldset'] ) || 'start' === $args['fieldset'];
			$has_fieldset_end   = ! isset( $args['fieldset'] ) || 'end'   === $args['fieldset'];

			// Unless it's an fieldset end or start ONLY, don't wrap helpers in a fieldset tag.
			if ( $has_fieldset_begin && $has_fieldset_end && substr( $field_type, 0, 7 ) === 'helper_' ) {
				$has_fieldset_begin = false;
				$has_fieldset_end   = false;
			}

			$has_fieldset = $has_fieldset_begin || $has_fieldset_end;

			if ( $has_fieldset_begin ) {
				echo '<fieldset class="fieldname-' . sanitize_html_class( $args['name'] ) . ' fieldtype-' . sanitize_html_class( $field_type ) . $depends . '">';
			}

			switch ( $field_type ) {//// Supprimer les labels si $label est vide. Supprimer les legend si pas de fieldset.
				case 'number' :
				case 'email' :
				case 'text' :

					$min = isset( $args['min'] ) ? ' min="' . (int) $args['min'] . '"' : '';
					$max = isset( $args['max'] ) ? ' max="' . (int) $args['max'] . '"' : '';

					$number_options = $field_type === 'number' ? $min . $max . ' class="small-text"' : '';
					$autocomplete   = in_array( $args['name'], array( 'consumer_key', 'consumer_email' ) ) ? ' autocomplete="off"' : '';
					$disabled       = false ? ' disabled="disabled"' : $readonly;
					$data_realtype  = 'password' != $field_type ? '' : ' data-realtype="password"';
					?>
					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
						<input <?php echo $title; ?><?php echo $autocomplete; ?><?php echo $pattern; ?><?php echo $required; ?><?php echo $disabled; ?><?php echo $data_realtype; ?> type="<?php echo $field_type; ?>"<?php echo $number_options; ?> id="<?php echo $args['label_for']; ?>" name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>]" value="<?php echo esc_attr( $value ); ?>" <?php echo $placeholder; ?><?php echo $readonly; ?>/>
					<?php echo $label; ?>
					</label>
					<?php
					break;

				case 'textarea' :

					$value = is_array( $value ) ? esc_textarea( implode( "\n" , $value ) ) : esc_textarea( $value );
					?>
					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
						<textarea id="<?php echo $args['label_for']; ?>" name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>]" cols="<?php echo $cols; ?>" rows="<?php echo $rows; ?>"<?php echo $readonly; ?>><?php echo $value; ?></textarea>
					</label>
					<?php
					break;

				case 'checkbox' :

					if ( isset( $args['label_screen'] ) ) {
						?>
						<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
						<?php
					}
					?>
					<label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
						<input type="checkbox" id="<?php echo $args['name']; ?>" class="<?php echo $class; ?>" name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>]" value="1"<?php echo $readonly; ?> <?php checked( $value, 1 ); ?> <?php echo $parent; ?>/> <?php echo $args['label']; ?>
					</label>
					<?php
					break;

				case 'select' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
						<select size="<?php echo $args['size']; ?>" multiple="multiple" id="<?php echo $args['name']; ?>" name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>]"<?php echo $readonly; ?>>
							<?php
							$value = (array) $value;

							foreach ( $args['options'] as $val => $title ) {
								$readonly = '_' !== $val[0] ? '' : ' readonly="readonly" disabled="disabled"';
								?>
								<option value="<?php echo $val; ?>" <?php selected( in_array( $val, $value ) ); echo $readonly;?>><?php echo $title; ?></option>
								<?php
							}
							?>
						</select>
						<?php echo $label; ?>
					</label>

					<?php
					break;

				case 'roles' :

					$value = (array) $value;
					$roles = new WP_Roles();
					$roles = $roles->get_names();
					$roles = array_map( 'translate_user_role', $roles );
					?>
					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
					foreach ( $roles as $val => $title ) {
						?>
						<label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
							<input type="checkbox" name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>][]" value="<?php echo $val; ?>"<?php checked( ! in_array( $val, $value ) ); ?>> <?php echo $title; ?>
						</label><br />
						<input type="hidden" name="<?php echo $option_name; ?>[hidden_<?php echo $args['name']; ?>][]" value="<?php echo $val; ?>">
						<?php
					}
					break;

				case 'checkboxes' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
					$value       = (array) $value;
					$radio_style = $radio_style ? ' class="radiobox"' : '';

					foreach ( $args['options'] as $val => $title ) {
						$readonly = '_' !== $val[0] ? '' : ' readonly="readonly" disabled="disabled"';
						?>
						<label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
							<input type="checkbox" id="<?php echo $args['name']; ?>_<?php echo $val; ?>"<?php echo $radio_style; ?> value="<?php echo $val; ?>"<?php checked( in_array( $val, $value ) ); ?> name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>][]"<?php echo $readonly; ?>> <?php echo $title; ?>
						</label>
						<?php echo '_' !== $val[0] ? '' : secupress_get_pro_version_string( '<span class="description">%s</span>' ); ?>
						<br />
						<?php
					}

					break;

				case 'countries' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
					$value = (array) $value;

					foreach ( $args['options'] as $code_country => $countries ) {
						$title = array_shift( $countries );
						?>
						<label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
							<input type="checkbox" class="<?php echo $args['name']; ?>" value="<?php echo $code_country; ?>"<?php checked( in_array( $code_country, $value ) ); ?>> <?php echo $title; ?> <em>(<?php _e( 'All countries', 'secupress' ); ?>)</em>
						</label>
						<br />
						<?php
						foreach ( $countries as $code => $title ) {
							?>
							&mdash; <label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
								<input type="checkbox" data-code-country="<?php echo $code_country; ?>" id="<?php echo $args['name']; ?>_<?php echo $code; ?>" value="<?php echo $code; ?>"<?php checked( in_array( $code, $value ) ); ?> name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>][]"<?php echo $readonly; ?>> <?php echo $title; ?>
							</label>
							<br />
							<?php
						}
						echo '<br />';
					}

					break;

				case 'radios' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php

					foreach ( $args['options'] as $val => $title ) {
						$readonly = '_' !== $val[0] ? '' : ' readonly="readonly" disabled="disabled"';
						?>
						<label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
							<input type="radio" id="<?php echo $args['name']; ?>_<?php echo $val; ?>" value="<?php echo $val; ?>"<?php checked( $val, $value ); ?> name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>][]"<?php echo $readonly; ?>> <?php echo $title; ?>
						</label>
						<?php echo '_' !== $val[0] ? '' : secupress_get_pro_version_string( '<span class="description">%s</span>' ); ?>
						<br />
						<?php
					}

					break;

				case 'radio' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
					foreach ( $args['options'] as $val => $title ) {
						$readonly = '_' !== $val[0] ? '' : ' readonly="readonly" disabled="disabled"';
						?>
						<label<?php echo $readonly ? ' class="readonly"' : ''; ?>>
							<input type="radio" id="<?php echo $args['name']; ?>_<?php echo $val; ?>" value="<?php echo $val; ?>"<?php checked( $value, $val ); ?> name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>]"<?php echo $readonly; ?>> <?php echo $title; ?>
						</label>
						<?php echo '_' !== $val[0] ? '' : secupress_get_pro_version_string( '<span class="description">%s</span>' ); ?>
						<br />
						<?php
					}

					break;

				case 'nonlogintimeslot' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
					$from_hour   = isset( $value['from_hour'] )   ? $value['from_hour']   : '';
					$from_minute = isset( $value['from_minute'] ) ? $value['from_minute'] : '';
					$to_hour     = isset( $value['to_hour'] )     ? $value['to_hour']     : '';
					$to_minute   = isset( $value['to_minute'] )   ? $value['to_minute']   : '';

					_e( 'Everyday', 'secupress' );
					echo '<br>';
					echo '<span style="display:inline-block;min-width:3em">' . _x( 'From', '*From* xx h xx mn To xx h xx mn', 'secupress' ) . '</span>';
					?>
					<label>
						<input type="number" class="small-text" min="0" max="23" id="<?php echo $args['name']; ?>_from_hour" value="<?php echo (int) $from_hour; ?>" name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>][from_hour]"<?php echo $readonly; ?>>
					</label> <?php _ex( 'h', 'hour', 'secupress' ); ?>
					<label>
						<input type="number" class="small-text" min="0" max="45" step="15" id="<?php echo $args['name']; ?>_from_minute" value="<?php echo (int) $from_minute; ?>" name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>][from_minute]"<?php echo $readonly; ?>>
					</label> <?php _ex( 'min', 'minute', 'secupress' ); ?>
					<br>
					<?php
					echo '<span style="display:inline-block;min-width:3em">' . _x( 'To', 'From xx h xx mn *To* xx h xx mn', 'secupress' ) . '</span>';
					?>
					<label>
						<input type="number" class="small-text" min="0" max="23" id="<?php echo $args['name']; ?>_to_hour" value="<?php echo (int) $to_hour; ?>" name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>][to_hour]"<?php echo $readonly; ?>>
					</label> <?php _ex( 'h', 'hour', 'secupress' ); ?>
					<label>
						<input type="number" class="small-text" min="0" max="45" step="15" id="<?php echo $args['name']; ?>_to_minute" value="<?php echo (int) $to_minute; ?>" name="<?php echo $option_name; ?>[<?php echo $args['name']; ?>][to_minute]"<?php echo $readonly; ?>>
					</label> <?php _ex( 'min', 'minute', 'secupress' ); ?>
					<?php

					break;

				case 'helper_description' :

					$description = isset( $args['description'] ) ? '<p class="description desc' . $class . $depends . '">' . $args['description'] . '</p>' : '';
					echo apply_filters( 'secupress_help', $description, $args['name'], 'description' );

					break;

				case 'helper_help' :

					$description = isset( $args['description'] ) ? '<p class="description help' . $class . $depends . '">' . $args['description'] . '</p>' : '';
					echo apply_filters( 'secupress_help', $description, $args['name'], 'help' );

				break;

				case 'helper_warning' :

					$description = isset( $args['description'] ) ? '<p class="description warning' . $class . $depends . '"><strong>' . __( 'Warning: ', 'secupress' ) . '</strong>' . $args['description'] . '</p>' : '';
					echo apply_filters( 'secupress_help', $description, $args['name'], 'warning' );

					break;

				default :
					if ( method_exists( $this, $field_type ) ) {
						call_user_func( array( $this, $field_type ) );
					} else {
						echo 'Type manquant ou incorrect'; // ne pas traduire
					}

			}

			if ( $has_fieldset_end ) {
				echo '</fieldset>';
			}

		}

	}

	/**
	 * Outputs the form used by the importers to accept the data to be imported
	 *
	 * @since 1.0
	 */
	protected function import_upload_form() {
		/**
		 * Filter the maximum allowed upload size for import files.
		 *
		 * @since (WordPress) 2.3.0
		 *
		 * @see wp_max_upload_size()
		 *
		 * @param int $max_upload_size Allowed upload size. Default 1 MB.
		 */
		$bytes      = apply_filters( 'import_upload_size_limit', wp_max_upload_size() ); // Filter from WP Core
		$size       = size_format( $bytes );
		$upload_dir = wp_upload_dir();
		$readonly = ! secupress_is_pro() ? ' readonly="readonly" disabled="disabled"' : '';
		if ( ! empty( $upload_dir['error'] ) ) {
			?><div class="error"><p><?php _e( 'Before you can upload your import file, you will need to fix the following error:', 'secupress' ); ?></p>
			<p><strong><?php echo $upload_dir['error']; ?></strong></p></div><?php
		} else {
			?>
			<p>
			<input type="file" id="upload" name="import" size="25"<?php echo $readonly; ?>/>
			<br />
			<label for="upload"><?php echo apply_filters( 'secupress_help', __( 'Choose a file from your computer:', 'secupress' ) . ' (' . sprintf( __( 'Maximum size: %s', 'secupress' ), $size ) . ')', 'upload', 'help' ); ?></label>
			<input type="hidden" name="max_file_size" value="<?php echo $bytes; ?>" />
			</p>
			<?php submit_button( __( 'Upload file and import settings', 'secupress' ), 'button', 'import', true, $readonly );
		}
	}


	/**
	 * Outputs the export button
	 *
	 * @since 1.0
	 */
	protected function export_form() {
		if ( secupress_is_pro() ) {
		?>
			<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export' ), 'secupress_export' ); ?>" id="export" class="button button-secondary secupressicon"><?php _e( 'Download settings', 'secupress' ); ?></a>
		<?php
		} else {
		?>
			<button readonly="readonly" class="button button-secondary" disabled="disabled"><?php _e( 'Download settings', 'secupress' ); ?></button>
		<?php
		}
	}

	/**
	 * Outputs the 404 logs
	 *
	 * @since 1.0
	 */
	protected function _404_logs() {
		//// tempo
		echo '<p><em>No 404 yet</em></p>';
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_clear_404' ), 'secupress_clear_404' ) . '" class="button button-secondary">' . __( 'Clear 404', 'secupress' ) . '</a>';
	}


	/**
	 * Displays the scheduled backups module
	 *
	 * @since 1.0
	 */
	protected function scheduled_backups() {
		//// tempo
		echo '<p><em>No scheduled backups yet, create one?</em></p>';
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_clear_alerts' ), 'secupress_clear_alerts' ) . '" class="button button-secondary">' . __( 'Clear Alerts', 'secupress' ) . '</a>';
	}

	/**
	 * Displays the alerts and add actions to delete it
	 *
	 * @since 1.0
	 */
	protected function alerts() {
		//// tempo
		echo '<p><em>No alerts found yet</em></p>';
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_clear_alerts' ), 'secupress_clear_alerts' ) . '" class="button button-secondary">' . __( 'Clear Alerts', 'secupress' ) . '</a>';
	}


	/**
	 * Displays the banned IPs and add actions to delete it
	 *
	 * @since 1.0
	 */
	protected function banned_ips() {
		//// tempo
		echo '<p><em>No Banned IPs found yet</em></p>';
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_clear_ips' ), 'secupress_clear_ips' ) . '" class="button button-secondary">' . __( 'Clear Banned IPs', 'secupress' ) . '</a>';
	}



	/**
	 * Displays WordPress logs
	 *
	 * @since 1.0
	 */
	protected function wp_logs() {
		//// tempo
		echo '<p><em>Nothing happens yet, how is that possible?</em></p>';
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_clear_wplogs' ), 'secupress_clear_wplogs' ) . '" class="button button-secondary">' . __( 'Clear WordPress Logs', 'secupress' ) . '</a>';
	}



	/**
	 * Displays the db backups and the CTA to launch one
	 *
	 * @since 1.0
	 */
	protected function backup_db() {
		//// tempo
		echo '<p><em>No Database Backups found yet, do one?</em></p>';
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_backup_db' ), 'secupress_backup_db' ) . '" class="button button-secondary">' . __( 'Backup my Database', 'secupress' ) . '</a>';
	}


	/**
	 * Displays the files backups and the CTA to launch one
	 *
	 * @since 1.0
	 */
	protected function backup_files() {
		//// tempo
		echo '<p><em>No Files Backups found yet, do one?</em></p>';
		$readonly = ! secupress_is_pro() ? ' readonly="readonly" disabled="disabled"' : '';
		echo '<a' . $readonly . ' href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_backup_files' ), 'secupress_backup_files' ) . '" class="button button-secondary">' . __( 'Backup my Files', 'secupress' ) . '</a>';
	}


	/**
	 * Scan the installation and search for modified files
	 *
	 * @since 1.0
	 */
	protected function file_scanner() {
		echo '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_get_file_scan' ), 'secupress_get_file_scan' ) . '" class="button button-secondary">' . __( 'Search for modified files', 'secupress' ) . '</a>';
	}


	/**
	 * Scan the installation and search for malicious files
	 *
	 * @since 1.0
	 */
	protected function virus_scanner() {
		$readonly = ! secupress_is_pro() ? ' readonly="readonly" disabled="disabled"' : '';
		echo '<a' . $readonly . ' href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_get_virus_scan' ), 'secupress_get_virus_scan' ) . '" class="button button-secondary">' . __( 'Search for malicious files', 'secupress' ) . '</a>';
	}


	/**
	 * Used to display buttons.
	 *
	 * @since 1.0
	 */
	// secupress_button()
	protected function field_button( $args ) {

		$button       = $args['button'];
		$desc         = isset( $args['helper_description'] ) ? $args['helper_description'] : null;
		$help         = isset( $args['helper_help'] )        ? $args['helper_help'] : null;
		$warning      = isset( $args['helper_warning'] )     ? $args['helper_warning'] : null;
		$id           = isset( $button['button_id'] )        ? ' id="' . sanitize_html_class( $button['button_id'] ) . '"' : null;
		$button_style = isset( $button['style'] )            ? 'button-' . sanitize_html_class( $button['style'] ) : 'button-secondary';
		$class        = sanitize_html_class( strip_tags( $button['button_label'] ) );

		if ( ! empty( $help ) ) {
			$help = '<p class="description help ' . $class . '">' . $help['description'] . '</p>';
		}
		if ( ! empty( $desc ) ) {
			$desc = '<p class="description desc ' . $class . '">' . $help['description'] . '</p>';
		}
		if ( ! empty( $warning ) ) {
			$warning = '<p class="description warning file-error ' . $class . '"><b>' . __( 'Warning: ', 'secupress' ) . '</b>' . $warning['description'] . '</p>';
		}
		?>
		<fieldset class="fieldname-<?php echo $class; ?> fieldtype-button">
			<?php
			if ( isset( $button['url'] ) ) {
				echo '<a href="' . esc_url( $button['url'] ) . '"' . $id . ' class="' . $button_style . ' secupressicon secupressicon-'. $class . '">' . wp_kses_post( $button['button_label'] ) . '</a>';
			}
			else {
				echo '<button type="button"' . $id . ' class="' . $button_style . ' secupressicon secupressicon-' . $class . '">' . wp_kses_post( $button['button_label'] ) . '</button>';
			}

			echo apply_filters( 'secupress_help', $desc,    sanitize_key( strip_tags( $button['button_label'] ) ), 'description' );
			echo apply_filters( 'secupress_help', $help,    sanitize_key( strip_tags( $button['button_label'] ) ), 'help' );
			echo apply_filters( 
				'secupress_help', 
				$warning, 
				sanitize_key( strip_tags( $button['button_label'] ) ), 
				'warning' );
			?>
		</fieldset>
		<?php
	}


	/**
	 * Output a correct name for setting fields
	 *
	 * @since 1.0
	 * @return string
	 **/
	final protected function get_field_name( $field ) {
		return "{$this->pluginnow}_{$field}";
	}


	// secupress_add_settings_field()
	protected function add_field( $title, $args, $fields ) {

		$args = wp_parse_args( $args, array(
			'name'        => '',
			'field_type'  => 'field',
			'description' => '',
		) );

		$callback = method_exists( $this, $args['field_type'] ) ? array( $this, $args['field_type'] ) : 'secupress_' . $args['field_type'];

		add_settings_field(
			'module_' . $this->modulenow . '|' . $this->pluginnow . '|' . $args['name'],
			$title . static::field_description( $args['description'] ),
			$callback,
			$this->get_section_id(),
			$this->get_section_id(),
			$fields
		);

		do_action( 'after_module_' . $this->modulenow . '|' . $this->pluginnow );

		return $this;
	}

	/**
	 * Like the real `do_settings_fields()` but `id` and `class` attributes can be added to the `tr` tag (the `class` attribute appeared in WP 4.3).
	 *
	 * @return void
	 */
	final protected static function do_settings_fields( $page, $section ) {
		global $wp_settings_fields;

		if ( ! isset( $wp_settings_fields[ $page ][ $section ] ) ) {
			return;
		}

		foreach ( (array) $wp_settings_fields[ $page ][ $section ] as $field ) {
			$id    = '';
			$class = '';

			if ( ! empty( $field['args']['id'] ) ) {
				$id = ' id="' . esc_attr( $field['args']['id'] ) . '"';
			}

			if ( ! empty( $field['args']['class'] ) ) {
				$class = $field['args']['class'];
			}

			if ( ! empty( $field['args']['depends'] ) ) {
				$field['args']['depends'] = explode( ' ', $field['args']['depends'] );
				$class .= ' depends-' . implode( ' depends-', $field['args']['depends'] );
			}

			if ( $class ) {
				$class = ' class="' . esc_attr( trim( $class ) ) . '"';
			}

			unset( $field['args']['class'], $field['args']['depends'] );

			echo "<tr{$id}{$class}>";

				if ( ! empty( $field['args']['label_for'] ) ) {
					echo '<th scope="row"><label for="' . esc_attr( $field['args']['label_for'] ) . '">' . $field['title'] . '</label></th>';
				} else {
					echo '<th scope="row">' . $field['title'] . '</th>';
				}

				echo '<td>';
				call_user_func( $field['callback'], $field['args'] );
				echo '</td>';

			echo '</tr>';
		}
	}


	// Other template tags =========================================================================

	// __secupress_module_switch_description() + __secupress_module_full_title()
	protected function print_section_description() {
		$key = $this->modulenow . '|' . $this->sectionnow;

		if ( ! empty( $this->sections_descriptions[ $key ] ) ) {
			echo '<div class="secupress-section-description"><i>';
				echo $this->sections_descriptions[ $key ];
			echo '</i></div>';
		}

		return $this;
	}


	// secupress_submit_button()
	protected static function submit_button( $type = 'primary large', $name = 'main_submit', $wrap = true, $other_attributes = null, $echo = true ) {
		if ( true === $wrap ) {
			$wrap = '<p class="submit">';
		} elseif ( $wrap ) {
			$wrap = '<p class="submit ' . sanitize_html_class( $wrap ) . '">';
		}

		$button = get_submit_button( __( 'Save All Changes', 'secupress' ), $type, $name, false, $other_attributes );

		if ( $wrap ) {
			$button = $wrap . $button . '</p>';
		}

		if ( ! $echo ) {
			return $button;
		}

		echo $button;
	}


	// Utilities ===================================================================================

	/**
	 * Output the $text in a P tag with .description class
	 *
	 * @since 1.0
	 *
	 * @param (string)$text : the last word of the secupress page slug
	*/
	public static function field_description( $text = '' ) {
		if ( '' !== $text ) {
			return '<p class="description">' . $text . '</p>';
		}
	}


	// Includes ====================================================================================

	final protected function require_settings_file( $module_file, $module ) {

		if ( file_exists( $module_file ) ) {
			$this->set_current_plugin( $module );

			require( $module_file );

			$this->do_sections();
		}

		return $this;
	}

}
