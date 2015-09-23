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

	protected static $modules;

	protected        $modulenow;  // Tab (page), like `users_login`.
	protected        $sectionnow; // Section, like `login_auth`.
	protected        $pluginnow;  // Field, like `double_auth`.
	protected        $sections_descriptions = array();


	// Instance ====================================================================================

	/**
	 * Returns the *Singleton* instance of this class.
	 *
	 * @return Singleton The *Singleton* instance.
	 */
	public static function get_instance() {
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

	final protected static function set_modules() {
		static::$modules = secupress_get_modules();
	}


	final protected function set_current_module() {
		$this->modulenow = isset( $_GET['module'] ) ? $_GET['module'] : 'welcome';
		$this->modulenow = array_key_exists( $this->modulenow, static::get_modules() ) && file_exists( SECUPRESS_MODULES_PATH . static::sanitize_filename( $this->modulenow ) . '/settings.php' ) ? $this->modulenow : 'welcome';
		return $this;
	}


	final public function set_current_section( $section ) {
		$this->sectionnow = $section;
		return $this;
	}


	final public function set_current_plugin( $plugin ) {
		$this->pluginnow = $plugin;
		return $this;
	}


	// Getters =====================================================================================

	final public static function get_modules() {
		if ( empty( static::$modules ) ) {
			static::set_modules();
		}

		return static::$modules;
	}


	final public function get_current_module() {
		return $this->modulenow;
	}


	final public function get_current_section() {
		return $this->sectionnow;
	}


	final public function get_current_plugin() {
		return $this->pluginnow;
	}


	/**
	 * Get a module title.
	 *
	 * @since 1.0
	 *
	 * @param (string)$module : the desired module
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
	 * @param (string)$module : the desired module
	*/
	final public function get_module_descriptions( $module = false ) {
		$modules = static::get_modules();
		$module  = $module ? $module : $this->modulenow;

		if ( ! empty( $modules[ $module ]['description'] ) ) {
			return (array) $modules[ $module ]['description'];
		}

		return array();
	}


	// Init ========================================================================================

	protected function init() {
		$this->set_current_module();
	}


	// Main template tags ==========================================================================

	public function print_page() {
		die( 'Method SecuPress_Settings::print_page() must be over-ridden in a sub-class.' );
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


	// Sections ====================================================================================

	//// secupress_add_settings_section()
	public function add_section( $title, $args = null ) {

		$args       = wp_parse_args( $args, array( 'with_roles' => false, 'with_save_button' => true ) );
		$actions    = '';
		$section_id = 'module_' . $this->modulenow . '|' . $this->sectionnow;

		if ( ! empty( $args['with_roles'] ) ) {
			$actions .= '<button type="button" class="hide-if-no-js no-button button-actions-title" aria-expanded="false" aria-controls="block-_affected_role">' . __( 'Roles', 'secupress' ) . ' <span class="dashicons dashicons-arrow-right" aria-hidden="true"></span></button>';
		}

		do_action( 'before_section_' . $this->sectionnow );

		add_settings_section(
			$section_id,
			$title . $actions,
			array( $this, 'print_section_description' ),
			$section_id
		);

		if ( empty( $args['with_roles'] ) ) {
			return $this;
		}

		$this->add_field(
			'<span class="dashicons dashicons-groups"></span> ' . __( 'Affected Roles', 'secupress' ),
			array(
				'description' => __( 'Which roles will be affected by this module?', 'secupress' ),
				'field_type'  => 'field',
				'name'        => 'affected_role',
			),
			array(
				'id'    => 'block-_affected_role',
				'class' => static::hidden_classes( 'hide-if-js block-_affected_role block-plugin_' . $this->pluginnow ),
				array(
					'type'         => 'roles',
					'default'      => array(), //// (TODO) not supported yet why not $args['with_roles']
					'name'         => $this->pluginnow . '_affected_role',
					'label_for'    => $this->pluginnow . '_affected_role',
					'label'        => '',
					'label_screen' => __( 'Affected Roles', 'secupress' ),
				),
				array(
					'type'         => 'helper_description',
					'name'         => $this->pluginnow . '_affected_role',
					'description'  => __( 'Future roles will be automatically checked.', 'secupress' )
				),
				array(
					'type'         => 'helper_warning',
					'name'         => $this->pluginnow . '_affected_role',
					'class'        => 'hide-if-js',
					'description'  => __( 'Select 1 role minimum', 'secupress' )
				),
			)
		);

		return $this;
	}


	// do_secupress_settings_sections() + secupress_do_secupress_settings_sections()
	protected function do_sections( $submit_button = true ) {

		$page = 'module_' . $this->modulenow . '|' . $this->sectionnow;

		echo '<div class="secublock">';
			static::do_settings_sections( $page );
		echo '</div>';

		if ( $submit_button ) {
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
	final protected static function do_settings_sections( $page ) {
		global $wp_settings_sections, $wp_settings_fields;

		if ( ! isset( $wp_settings_sections[ $page ] ) ) {
			return;
		}

		foreach ( (array) $wp_settings_sections[ $page ] as $section ) {
			if ( $section['title'] ) {
				echo "<h3>{$section['title']}</h3>\n";
			}

			if ( $section['callback'] ) {
				call_user_func( $section['callback'], $section );
			}

			if ( ! isset( $wp_settings_fields ) || ! isset( $wp_settings_fields[ $page ] ) || ! isset( $wp_settings_fields[ $page ][ $section['id'] ] ) ) {
				continue;
			}

			echo '<table class="form-table">';
				static::do_settings_fields( $page, $section['id'] );
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

			$args['label_for'] = isset( $args['label_for'] )   ? $args['label_for'] : '';
			$args['name']      = isset( $args['name'] )        ? $args['name'] : $args['label_for'];
			$parent            = isset( $args['parent'] )      ? 'data-parent="' . sanitize_html_class( $args['parent'] ). '"' : null;
			$placeholder       = isset( $args['placeholder'] ) ? 'placeholder="'. $args['placeholder'].'" ' : '';
			$label             = isset( $args['label'] )       ? $args['label'] : '';
			$required          = isset( $args['required'] )    ? ' data-required="required" data-aria-required="true"' : '';
			$pattern           = isset( $args['pattern'] )     ? ' data-pattern="' . $args['pattern'] . '"' : '';
			$title             = isset( $args['title'] )       ? ' title="' . $args['title'] . '"' : '';
			$default           = isset( $args['default'] )     ? $args['default'] : '';
			$cols              = isset( $args['cols'] )        ? (int) $args['cols'] : 50;
			$rows              = isset( $args['rows'] )        ? (int) $args['rows'] : 5;
			$size              = isset( $args['size'] )        ? (int) $args['size'] : 1;
			$readonly          = ! empty( $args['readonly'] )  ? ' readonly="readonly" disabled="disabled"' : '';
			$class             = isset( $args['class'] )       ? $args['class'] : '';

			if ( is_array( $class ) ) {
				$class = implode( ' ', array_map( 'sanitize_html_class', $class ) );
			}
			else {
				$class = sanitize_html_class( $class );
			}

			$class .= ( $parent ) ? ' has-parent' : null;

			if ( ! isset( $args['fieldset'] ) || 'start' === $args['fieldset'] ) {
				echo '<fieldset class="fieldname-' . sanitize_html_class( $args['name'] ) . ' fieldtype-' . sanitize_html_class( $args['type'] ) . '">';
			}

			switch ( $args['type'] ) {
				case 'number' :
				case 'email' :
				case 'text' :

					$value = esc_attr( secupress_get_module_option( $args['name'] ) );
					if ( ! $value ) {
						$value = $default;
					}
					$min = isset( $args['min'] ) ? ' min="' . (int) $args['min'] . '"' : '';
					$max = isset( $args['max'] ) ? ' max="' . (int) $args['max'] . '"' : '';

					$number_options = $args['type'] === 'number' ? $min . $max . ' class="small-text"' : '';
					$autocomplete   = in_array( $args['name'], array( 'consumer_key', 'consumer_email' ) ) ? ' autocomplete="off"' : '';
					$disabled       = false ? ' disabled="disabled"' : $readonly;						////
					$data_realtype  = 'password' != $args['type'] ? '' : ' data-realtype="password"';
					?>
					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label>
						<input <?php echo $title; ?><?php echo $autocomplete; ?><?php echo $pattern; ?><?php echo $required; ?><?php echo $disabled; ?><?php echo $data_realtype; ?> type="<?php echo $args['type']; ?>"<?php echo $number_options; ?> id="<?php echo $args['label_for']; ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>]" value="<?php echo $value; ?>" <?php echo $placeholder; ?><?php echo $readonly; ?>/>
						<?php echo $label; ?>
					</label>
					<?php
					break;

				case 'password' :

					$value        = esc_attr( secupress_get_module_option( $args['name'] ) );
					$data_nocheck = $value ? ' data-nocheck="true"' : '';
					$disabled     = false ? ' disabled="disabled"' : $readonly;
					?>
					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label>
						<input autocomplete="off" data-realtype="password" <?php echo $data_nocheck; ?><?php echo $title; ?><?php echo $pattern; ?><?php echo $required; ?><?php echo $disabled; ?> type="password" id="<?php echo $args['label_for']; ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>]" value="" <?php echo $readonly; ?>/>
						<input type="text" tabindex="-1" id="password_strength_pattern"<?php echo $data_nocheck; ?> data-pattern="[3-4]" title="<?php esc_attr_e( 'Minimum Strength Level: Medium', 'secupress' ); ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[password_strength_value]" value="0" id="password_strength_value" />
						<?php echo $label; ?>
						<i class="hide-if-no-js"><?php printf( __( 'Required: %s', 'secupress' ), _x( 'Medium', 'password strength' ) ); ?></i>
						<br><span id="password-strength" class="hide-if-no-js"></span>
					</label>
					<?php
					break;

				case 'textarea' :

					$t_temp = secupress_get_module_option( $args['name'], '' );
					$value  = ! empty( $t_temp ) ? esc_textarea( implode( "\n" , $t_temp ) ) : '';
					if ( ! $value ){
						$value = $default;
					}
					?>
					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label>
						<textarea id="<?php echo $args['label_for']; ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>]" cols="<?php echo $cols; ?>" rows="<?php echo $rows; ?>"<?php echo $readonly; ?>><?php echo $value; ?></textarea>
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
					<label>
						<input type="checkbox" id="<?php echo $args['name']; ?>" class="<?php echo $class; ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>]" value="1"<?php echo $readonly; ?> <?php checked( secupress_get_module_option( $args['name'], 0 ), 1 ); ?> <?php echo $parent; ?>/> <?php echo $args['label']; ?>
					</label>
					<?php
					break;

				case 'select' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<label>
						<select size="<?php echo $args['size']; ?>" multiple="multiple" id="<?php echo $args['name']; ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>]"<?php echo $readonly; ?>>
							<?php
							foreach ( $args['options'] as $val => $title ) {
								if ( '_' === $val[0] ) {
									$title .= ' (' . __( 'Premium', 'secupress' ) . ')';
								}
								?>
								<option value="<?php echo $val; ?>" <?php selected( secupress_get_module_option( $args['name'] ) == $val || in_array( $val, secupress_get_module_option( $args['name'], array() ) ) ); ?>><?php echo $title; ?></option>
								<?php
							}
							?>
						</select>
						<?php echo $label; ?>
					</label>

					<?php
					break;

				case 'roles' :

					$roles = new WP_Roles();
					$roles = $roles->get_names();
					$roles = array_map( 'translate_user_role', $roles );
					?>
					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
					foreach ( $roles as $val => $title ) {
						?>
						<label>
							<input type="checkbox" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>][]" value="<?php echo $val; ?>"<?php checked( ! in_array( $val, secupress_get_module_option( $args['name'], array() ) ) ); ?>> <?php echo $title; ?>
						</label><br />
						<input type="hidden" name="secupress_<?php echo $this->modulenow; ?>_settings[hidden_<?php echo $args['name']; ?>][]" value="<?php echo $val; ?>">
						<?php
					}
					break;

				case 'checkboxes' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
					foreach ( $args['options'] as $val => $title ) {
						if ( '_' === $val[0] ) {
							$title .= ' (' . __( 'Premium', 'secupress' ) . ')';
						}
						?>
						<label>
							<input type="checkbox" id="<?php echo $args['name']; ?>_<?php echo $val; ?>" value="<?php echo $val; ?>"<?php checked( in_array( $val, (array) secupress_get_module_option( $args['name'] ) ) ); ?> name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>][]"<?php echo $readonly; ?>> <?php echo $title; ?>
						</label><br />
						<?php
					}

					break;

				case 'radio' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
					foreach ( $args['options'] as $val => $title ) {
						if ( '_' === $val[0] ) {
							$title .= ' (' . __( 'Premium', 'secupress' ) . ')';
						}
						?>
						<label>
							<input type="radio" id="<?php echo $args['name']; ?>_<?php echo $val; ?>" value="<?php echo $val; ?>"<?php checked( secupress_get_module_option( $args['name'] ), $val ); ?> name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>]"<?php echo $readonly; ?>> <?php echo $title; ?>
						</label><br />
						<?php
					}

					break;

				case 'nonlogintimeslot' : ?>

					<legend class="screen-reader-text"><span><?php echo $args['label_screen']; ?></span></legend>
					<?php
					$value       = secupress_get_module_option( $args['name'] );
					$from_hour   = isset( $value['from_hour'] ) ? $value['from_hour'] : '';
					$from_minute = isset( $value['from_minute'] ) ? $value['from_minute'] : '';
					$to_hour     = isset( $value['to_hour'] ) ? $value['to_hour'] : '';
					$to_minute   = isset( $value['to_minute'] ) ? $value['to_minute'] : '';

					_e( 'Everyday', 'secupress' ); ////
					echo '<br>';
					echo '<span style="display:inline-block;min-width:3em">' . _x( 'From', '*From* xx h xx mn To xx h xx mn', 'secupress' ) . '</span>';
					?>
					<label>
						<input type="number" class="small-text" min="0" max="23" id="<?php echo $args['name']; ?>_from_hour" value="<?php echo (int) $from_hour; ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>][from_hour]"<?php echo $readonly; ?>>
					</label> <?php _ex( 'h', 'hour', 'secupress' ); ?>
					<label>
						<input type="number" class="small-text" min="0" max="45" step="15" id="<?php echo $args['name']; ?>_from_minute" value="<?php echo (int) $from_minute; ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>][from_minute]"<?php echo $readonly; ?>>
					</label> <?php _ex( 'min', 'minute', 'secupress' ); ?>
					<br>
					<?php
					echo '<span style="display:inline-block;min-width:3em">' . _x( 'To', 'From xx h xx mn *To* xx h xx mn', 'secupress' ) . '</span>';
					?>
					<label>
						<input type="number" class="small-text" min="0" max="23" id="<?php echo $args['name']; ?>_to_hour" value="<?php echo (int) $to_hour; ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>][to_hour]"<?php echo $readonly; ?>>
					</label> <?php _ex( 'h', 'hour', 'secupress' ); ?>
					<label>
						<input type="number" class="small-text" min="0" max="45" step="15" id="<?php echo $args['name']; ?>_to_minute" value="<?php echo (int) $to_minute; ?>" name="secupress_<?php echo $this->modulenow; ?>_settings[<?php echo $args['name']; ?>][to_minute]"<?php echo $readonly; ?>>
					</label> <?php _ex( 'min', 'minute', 'secupress' ); ?>
					<?php

					break;

				case 'helper_description' :

					$description = isset( $args['description'] ) ? '<p class="description desc ' . $class . '">' . $args['description'] . '</p>' : '';
					echo apply_filters( 'secupress_help', $description, $args['name'], 'description' );

					break;

				case 'helper_help' :

					$description = isset( $args['description'] ) ? '<p class="description help ' . $class . '">' . $args['description'] . '</p>' : '';
					echo apply_filters( 'secupress_help', $description, $args['name'], 'help' );

				break;

				case 'helper_warning' :

					$description = isset( $args['description'] ) ? '<p class="description warning ' . $class . '"><b>' . __( 'Warning: ', 'secupress' ) . '</b>' . $args['description'] . '</p>' : '';
					echo apply_filters( 'secupress_help', $description, $args['name'], 'warning' );

					break;
				/*
				case 'secupress_export_form' : ?>

					<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_export' ), 'secupress_export' ); ?>" id="export" class="button button-secondary secupressicon"><?php _e( 'Download options', 'secupress' ); ?></a>
					<?php
					break;

				case 'secupress_import_upload_form' :

					secupress_import_upload_form( 'secupress_importer' );

					break;
				*/
				default :

					echo 'Type manquant ou incorrect'; // ne pas traduire

			}

			if ( ! isset( $args['fieldset'] ) || 'end' == $args['fieldset'] ) {
				echo '</fieldset>';
			}

		}

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
			$desc = '<p class="description desc ' . $class . '">' . $desc['description'] . '</p>';
		}
		if ( ! empty( $warning ) ) {
			$warning = '<p class="description warning file-error ' . $class . '"><b>' . __( 'Warning: ', 'secupress' ) . '</b>' . $warning['description'] . '</p>';
		}
		?>
		<fieldset class="toto fieldname-<?php echo $class; ?> fieldtype-button">
			<?php
			if ( isset( $button['url'] ) ) {
				echo '<a href="' . esc_url( $button['url'] ) . '"' . $id . ' class="' . $button_style . ' secupressicon secupressicon-'. $class . '">' . wp_kses_post( $button['button_label'] ) . '</a>';
			}
			else {
				echo '<button type="button"' . $id . ' class="' . $button_style . ' secupressicon secupressicon-' . $class . '">' . wp_kses_post( $button['button_label'] ) . '</button>';
			}

			echo apply_filters( 'secupress_help', $desc,    sanitize_key( strip_tags( $button['button_label'] ) ), 'description' );
			echo apply_filters( 'secupress_help', $help,    sanitize_key( strip_tags( $button['button_label'] ) ), 'help' );
			echo apply_filters( 'secupress_help', $warning, sanitize_key( strip_tags( $button['button_label'] ) ), 'warning' );
			?>
		</fieldset>
		<?php
	}


	// secupress_add_settings_field()
	public function add_field( $title, $args, $fields ) {

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
			'module_' . $this->modulenow . '|' . $this->sectionnow,
			'module_' . $this->modulenow . '|' . $this->sectionnow,
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
				$class = ' class="' . esc_attr( $field['args']['class'] ) . '"';
			}

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


	// Includes ====================================================================================

	final public function load_module_settings() {
		$module_file = SECUPRESS_MODULES_PATH . static::sanitize_filename( $this->modulenow ) . '/settings.php';

		if ( file_exists( $module_file ) ) {
			require( $module_file );
		}

		return $this;
	}


	// secupress_load_settings()
	final public function load_plugin_settings( $plugin ) {
		$plugin_file = SECUPRESS_MODULES_PATH . static::sanitize_filename( $this->modulenow ) . '/settings/' . static::sanitize_filename( $plugin ) . '.php';

		if ( file_exists( $plugin_file ) ) {
			$this->set_current_plugin( $plugin );

			require( $plugin_file );

			$this->do_sections();
		}

		return $this;
	}


	public static function sanitize_filename( $filename ) {
		return strtolower( str_replace( '_', '-', sanitize_key( $filename ) ) );
	}


	// Other template tags =========================================================================

	// __secupress_module_switch_description() + __rocket_module_full_title()
	public function print_section_description() {
		$key = $this->modulenow . '|' . $this->sectionnow;

		if ( ! empty( $this->sections_descriptions[ $key ] ) ) {
			echo '<div class="notice notice-success"><i>';
				echo $this->sections_descriptions[ $key ];
			echo '</i></div>';
		}

		return $this;
	}


	public function set_section_description( $description ) {
		$key = $this->modulenow . '|' . $this->sectionnow;

		$this->sections_descriptions[ $key ] = $description;

		return $this;
	}


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


	// __secupress_get_hidden_classes()
	public static function hidden_classes( $classes ) {
		return 'hide-if-js block-hidden ' . $classes;
	}


	// secupress_submit_button()
	public static function submit_button( $type = 'primary large', $name = 'main_submit', $wrap = true, $other_attributes = null, $echo = true ) {
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

}
