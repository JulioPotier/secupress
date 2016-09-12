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
					$suffix = secupress_is_pro() ? '' : '-pro';
					?>
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
			$icon   = isset( $module['icon'] ) ? $module['icon'] : 'secupress-simple';
			$class  = $this->get_current_module() === $key ? 'active' : '';
			$class .= ! empty( $module['mark_as_pro'] ) ? ' secupress-pro-module' : '';

			// Skip Get Pro exception.
			if ( 'get-pro' === $key ) {
				continue;
			}
			?>
			<li>
				<a href="<?php echo esc_url( secupress_admin_url( 'modules', $key ) ); ?>" class="<?php echo $class; ?> module-<?php echo sanitize_key( $key ); ?>">
					<span class="secupress-tab-name"><?php echo $module['title']; ?></span>
					<span class="secupress-tab-summary"><?php echo $module['summaries']['small']; ?></span>
					<i class="icon-<?php echo $icon; ?>" aria-hidden="true"></i>
				</a>
			</li>
			<?php
		}

		// Prints last tab "Get Pro" is current user is not a pro one.
		if ( ! secupress_is_pro() ) {
			?>
			<li>
				<a href="<?php echo esc_url( secupress_admin_url( 'modules', 'get-pro' ) ); ?>" class="module-pro">
					<span class="secupress-tab-name"><?php esc_html_e( 'Get Pro', 'secupress' ); ?></span>
					<span class="secupress-tab-summary"><?php esc_html_e( 'Choose your licence', 'secupress' ); ?></span>
					<i class="icon-secupress-simple" aria-hidden="true"></i>
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
		<form id="secupress-module-form-settings" method="post" action="<?php echo $this->get_form_action(); ?>">
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
		// No module.
		if ( 'welcome' === $this->get_current_module() ) {
			$this->load_module_settings();
			return;
		}
		// Get Pro Page.
		if ( 'get-pro' === $this->get_current_module() ) {
			$this->load_module_settings();
			return;
		}
		?>
		<div class="secupress-tab-content-header">
			<?php
			$this->print_module_title();
			$this->print_module_description();
			$this->print_module_icon();
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
		$this->set_section_description( __( 'If you need to reset this module\'s settings to the default ones, you just have to do it here, the best settings for your site will be set.', 'secupress' ) );
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
			echo '<i class="icon-' . $this->get_module_icon() . '" aria-hidden="true"></i>' . "\n";
		}
		return $this;
	}


	// Specific fields =============================================================================.

	/**
	 * Non login time slot field.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function countries( $args ) {
		$name_attribute = 'secupress_' . $this->modulenow . '_settings[' . $args['name'] . ']';

		// Value.
		if ( isset( $args['value'] ) ) {
			$value = $args['value'];
		} else {
			$value = secupress_get_module_option( $args['name'] );
		}

		if ( is_null( $value ) ) {
			$value = $args['default'];
		}
		$value = array_flip( (array) array_filter( $value ) );

		// Attributes.
		$attributes = '';
		if ( ! empty( $args['attributes'] ) ) {
			foreach ( $args['attributes'] as $attribute => $attribute_value ) {
				$attributes .= ' ' . $attribute . '="' . esc_attr( $attribute_value ) . '"';
			}
		}
		$disabled_class = ! empty( $args['attributes']['disabled'] ) ? ' disabled' : '';
		$disabled_attr  = $disabled_class ? ' class="disabled"' : '';
		$_countries     = array( 'AF' => array( 0 => 'Africa', 'AO' => 'Angola', 'BF' => 'Burkina Faso', 'BI' => 'Burundi', 'BJ' => 'Benin', 'BW' => 'Botswana', 'CD' => 'Congo, The Democratic Republic of the', 'CF' => 'Central African Republic', 'CG' => 'Congo', 'CI' => 'Cote D\'Ivoire', 'CM' => 'Cameroon', 'CV' => 'Cape Verde', 'DJ' => 'Djibouti', 'DZ' => 'Algeria', 'EG' => 'Egypt', 'EH' => 'Western Sahara', 'ER' => 'Eritrea', 'ET' => 'Ethiopia', 'GA' => 'Gabon', 'GH' => 'Ghana', 'GM' => 'Gambia', 'GN' => 'Guinea', 'GQ' => 'Equatorial Guinea', 'GW' => 'Guinea-Bissau', 'KE' => 'Kenya', 'KM' => 'Comoros', 'LR' => 'Liberia', 'LS' => 'Lesotho', 'LY' => 'Libya', 'MA' => 'Morocco', 'MG' => 'Madagascar', 'ML' => 'Mali', 'MR' => 'Mauritania', 'MU' => 'Mauritius', 'MW' => 'Malawi', 'MZ' => 'Mozambique', 'NA' => 'Namibia', 'NE' => 'Niger', 'NG' => 'Nigeria', 'RE' => 'Reunion', 'RW' => 'Rwanda', 'SC' => 'Seychelles', 'SD' => 'Sudan', 'SH' => 'Saint Helena', 'SL' => 'Sierra Leone', 'SN' => 'Senegal', 'SO' => 'Somalia', 'ST' => 'Sao Tome and Principe', 'SZ' => 'Swaziland', 'TD' => 'Chad', 'TG' => 'Togo', 'TN' => 'Tunisia', 'TZ' => 'Tanzania, United Republic of', 'UG' => 'Uganda', 'YT' => 'Mayotte', 'ZA' => 'South Africa', 'ZM' => 'Zambia', 'ZW' => 'Zimbabwe', 'SS' => 'South Sudan' ), 'AN' => array( 0 => 'Antarctica', 'AQ' => 'Antarctica', 'BV' => 'Bouvet Island', 'GS' => 'South Georgia and the South Sandwich Islands', 'HM' => 'Heard Island and McDonald Islands', 'TF' => 'French Southern Territories' ), 'AS' => array( 0 => 'Asia', 'AP' => 'Asia/Pacific Region', 'AE' => 'United Arab Emirates', 'AF' => 'Afghanistan', 'AM' => 'Armenia', 'AZ' => 'Azerbaijan', 'BD' => 'Bangladesh', 'BH' => 'Bahrain', 'BN' => 'Brunei Darussalam', 'BT' => 'Bhutan', 'CC' => 'Cocos (Keeling) Islands', 'CN' => 'China', 'CX' => 'Christmas Island', 'CY' => 'Cyprus', 'GE' => 'Georgia', 'HK' => 'Hong Kong', 'ID' => 'Indonesia', 'IL' => 'Israel', 'IN' => 'India', 'IO' => 'British Indian Ocean Territory', 'IQ' => 'Iraq', 'IR' => 'Iran, Islamic Republic of', 'JO' => 'Jordan', 'JP' => 'Japan', 'KG' => 'Kyrgyzstan', 'KH' => 'Cambodia', 'KP' => 'Korea, Democratic People\'s Republic of', 'KR' => 'Korea, Republic of', 'KW' => 'Kuwait', 'KZ' => 'Kazakhstan', 'LA' => 'Lao People\'s Democratic Republic', 'LB' => 'Lebanon', 'LK' => 'Sri Lanka', 'MM' => 'Myanmar', 'MN' => 'Mongolia', 'MO' => 'Macau', 'MV' => 'Maldives', 'MY' => 'Malaysia', 'NP' => 'Nepal', 'OM' => 'Oman', 'PH' => 'Philippines', 'PK' => 'Pakistan', 'PS' => 'Palestinian Territory', 'QA' => 'Qatar', 'SA' => 'Saudi Arabia', 'SG' => 'Singapore', 'SY' => 'Syrian Arab Republic', 'TH' => 'Thailand', 'TJ' => 'Tajikistan', 'TM' => 'Turkmenistan', 'TL' => 'Timor-Leste', 'TW' => 'Taiwan', 'UZ' => 'Uzbekistan', 'VN' => 'Vietnam', 'YE' => 'Yemen' ), 'EU' => array( 0 => 'Europe', 'AD' => 'Andorra', 'AL' => 'Albania', 'AT' => 'Austria', 'BA' => 'Bosnia and Herzegovina', 'BE' => 'Belgium', 'BG' => 'Bulgaria', 'BY' => 'Belarus', 'CH' => 'Switzerland', 'CZ' => 'Czech Republic', 'DE' => 'Germany', 'DK' => 'Denmark', 'EE' => 'Estonia', 'ES' => 'Spain', 'FI' => 'Finland', 'FO' => 'Faroe Islands', 'FR' => 'France', 'GB' => 'United Kingdom', 'GI' => 'Gibraltar', 'GR' => 'Greece', 'HR' => 'Croatia', 'HU' => 'Hungary', 'IE' => 'Ireland', 'IS' => 'Iceland', 'IT' => 'Italy', 'LI' => 'Liechtenstein', 'LT' => 'Lithuania', 'LU' => 'Luxembourg', 'LV' => 'Latvia', 'MC' => 'Monaco', 'MD' => 'Moldova, Republic of', 'MK' => 'Macedonia', 'MT' => 'Malta', 'NL' => 'Netherlands', 'NO' => 'Norway', 'PL' => 'Poland', 'PT' => 'Portugal', 'RO' => 'Romania', 'RU' => 'Russian Federation', 'SE' => 'Sweden', 'SI' => 'Slovenia', 'SJ' => 'Svalbard and Jan Mayen', 'SK' => 'Slovakia', 'SM' => 'San Marino', 'TR' => 'Turkey', 'UA' => 'Ukraine', 'VA' => 'Holy See (Vatican City State)', 'RS' => 'Serbia', 'ME' => 'Montenegro', 'AX' => 'Aland Islands', 'GG' => 'Guernsey', 'IM' => 'Isle of Man', 'JE' => 'Jersey' ), 'OC' => array( 0 => 'Oceania', 'AS' => 'American Samoa', 'AU' => 'Australia', 'CK' => 'Cook Islands', 'FJ' => 'Fiji', 'FM' => 'Micronesia, Federated States of', 'GU' => 'Guam', 'KI' => 'Kiribati', 'MH' => 'Marshall Islands', 'MP' => 'Northern Mariana Islands', 'NC' => 'New Caledonia', 'NF' => 'Norfolk Island', 'NR' => 'Nauru', 'NU' => 'Niue', 'NZ' => 'New Zealand', 'PF' => 'French Polynesia', 'PG' => 'Papua New Guinea', 'PN' => 'Pitcairn Islands', 'PW' => 'Palau', 'SB' => 'Solomon Islands', 'TK' => 'Tokelau', 'TO' => 'Tonga', 'TV' => 'Tuvalu', 'UM' => 'United States Minor Outlying Islands', 'VU' => 'Vanuatu', 'WF' => 'Wallis and Futuna', 'WS' => 'Samoa' ), 'NA' => array( 0 => 'North America', 'AG' => 'Antigua and Barbuda', 'AI' => 'Anguilla', 'CW' => 'Curacao', 'AW' => 'Aruba', 'BB' => 'Barbados', 'BM' => 'Bermuda', 'BS' => 'Bahamas', 'BZ' => 'Belize', 'CA' => 'Canada', 'CR' => 'Costa Rica', 'CU' => 'Cuba', 'DM' => 'Dominica', 'DO' => 'Dominican Republic', 'SX' => 'Sint Maarten (Dutch part)', 'GD' => 'Grenada', 'GL' => 'Greenland', 'GP' => 'Guadeloupe', 'GT' => 'Guatemala', 'HN' => 'Honduras', 'HT' => 'Haiti', 'JM' => 'Jamaica', 'KN' => 'Saint Kitts and Nevis', 'KY' => 'Cayman Islands', 'LC' => 'Saint Lucia', 'MQ' => 'Martinique', 'MS' => 'Montserrat', 'MX' => 'Mexico', 'NI' => 'Nicaragua', 'PA' => 'Panama', 'PM' => 'Saint Pierre and Miquelon', 'PR' => 'Puerto Rico', 'SV' => 'El Salvador', 'TC' => 'Turks and Caicos Islands', 'TT' => 'Trinidad and Tobago', 'US' => 'United States', 'VC' => 'Saint Vincent and the Grenadines', 'VG' => 'Virgin Islands, British', 'VI' => 'Virgin Islands, U.S.', 'BL' => 'Saint Barthelemy', 'MF' => 'Saint Martin', 'BQ' => 'Bonaire, Saint Eustatius and Saba' ), 'SA' => array( 0 => 'South America', 'AR' => 'Argentina', 'BO' => 'Bolivia', 'BR' => 'Brazil', 'CL' => 'Chile', 'CO' => 'Colombia', 'EC' => 'Ecuador', 'FK' => 'Falkland Islands (Malvinas)', 'GF' => 'French Guiana', 'GY' => 'Guyana', 'PE' => 'Peru', 'PY' => 'Paraguay', 'SR' => 'Suriname', 'UY' => 'Uruguay', 'VE' => 'Venezuela' ) );

		foreach ( $_countries as $code_country => $countries ) {
			$title   = array_shift( $countries );
			$checked = array_intersect_key( $value, $countries );
			$checked = ! empty( $checked );
			?>
			<label class="continent<?php echo $disabled_class; ?>">
				<input type="checkbox" value="continent-<?php echo $code_country; ?>"<?php checked( $checked ); ?><?php echo $attributes; ?>>
				<?php echo '<span class="label-text">' . $title . '</span>'; ?>
			</label>
			<button type="button" class="hide-if-no-js expand_country"><img src="data:image/gif;base64,R0lGODlhEAAQAMQAAAAAAM/Iu3iYtcK4qPX18bDC09/b0ubm5v///9jTye3t59LMv8a+ruXh2tzYz/j4+PDw7NbRxuTh2f///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAUUABMALAAAAAAQABAAAAVI4CSOZGmeaKqubFkIcCwUp4DcOCLUOHA/O5PgQQQ8II1gSUAAOJ0GJUkAgSgAB4lDOhJoE4DIIsAVCRaMgVpdnrxkMFprjgoBADs=" alt="+" title="<?php esc_attr__( 'Expand', 'secupress' ); ?>" /></button>
			<fieldset class="hide-if-js">
				<legend class="screen-reader-text"><span><?php echo $title; ?></span></legend>
				<?php
				foreach ( $countries as $code => $title ) {
					$args['label_for'] = $args['name'] . '_' . $code;
					?>
					<div>
						<span class="secupress-tree-dash"></span>
						<label<?php echo $disabled_attr; ?>>
							<input type="checkbox" id="<?php echo $args['label_for']; ?>" name="<?php echo $name_attribute; ?>[]" value="<?php echo $code; ?>"<?php checked( isset( $value[ $code ] ) ); ?> data-code-country="<?php echo $code_country; ?>"<?php echo $attributes; ?>>
							<?php echo '<span class="label-text">' . $title . '</span>'; ?>
						</label>
					</div>
					<?php
				}
				?>
			</fieldset>
			<br/>
			<?php
		}
	}


	/**
	 * Non login time slot field.
	 *
	 * @since 1.0
	 *
	 * @param (array) $args An array of parameters. See `::field()`.
	 */
	protected function non_login_time_slot( $args ) {
		$name_attribute = 'secupress_' . $this->modulenow . '_settings[' . $args['name'] . ']';

		// Value.
		if ( isset( $args['value'] ) ) {
			$value = $args['value'];
		} else {
			$value = secupress_get_module_option( $args['name'] );
		}

		if ( is_null( $value ) ) {
			$value = $args['default'];
		}

		$from_hour   = isset( $value['from_hour'] )   ? (int) $value['from_hour']   : 0;
		$from_minute = isset( $value['from_minute'] ) ? (int) $value['from_minute'] : 0;
		$to_hour     = isset( $value['to_hour'] )     ? (int) $value['to_hour']     : 0;
		$to_minute   = isset( $value['to_minute'] )   ? (int) $value['to_minute']   : 0;

		// Attributes.
		$attributes = ' type="text" class="small-text" size="2" maxlength="2" autocomplete="off"';
		if ( ! empty( $args['attributes'] ) ) {
			foreach ( $args['attributes'] as $attribute => $attribute_value ) {
				$attributes .= ' ' . $attribute . '="' . esc_attr( $attribute_value ) . '"';
			}
		}

		echo $args['label'] ? '<p id="' . $args['name'] . '-time-slot-label">' . $args['label'] . '</p>' : '';
		?>
		<fieldset aria-labelledby="<?php echo $args['name']; ?>-time-slot-label">
			<legend class="screen-reader-text"><?php _e( 'Start hour and minute', 'secupress' ); ?></legend>
			<label>
				<span class="label-before" aria-hidden="true"><?php _ex( 'From', 'starting hour + minute', 'secupress' ); ?></span>
				<span class="screen-reader-text"><?php _e( 'Hour' ); ?></span>
				<input id="<?php echo $args['name']; ?>_from_hour" name="<?php echo $name_attribute; ?>[from_hour]" value="<?php echo str_pad( $from_hour, 2, 0, STR_PAD_LEFT ); ?>" pattern="0?[0-9]|1[0-9]|2[0-3]"<?php echo $attributes; ?>>
				<span aria-hidden="true"><?php _ex( 'h', 'hour', 'secupress' ); ?></span>
			</label>
			<label>
				<span class="screen-reader-text"><?php _e( 'Minute' ); ?></span>
				<input id="<?php echo $args['name']; ?>_from_minute" name="<?php echo $name_attribute; ?>[from_minute]" value="<?php echo str_pad( $from_minute, 2, 0, STR_PAD_LEFT ); ?>" pattern="0?[0-9]|[1-5][0-9]"<?php echo $attributes; ?>>
				<span aria-hidden="true"><?php _ex( 'min', 'minute', 'secupress' ); ?></span>
			</label>
		</fieldset>

		<fieldset aria-labelledby="<?php echo $args['name']; ?>-time-slot-label">
			<legend class="screen-reader-text"><?php _e( 'End hour and minute', 'secupress' ); ?></legend>
			<label>
				<span class="label-before" aria-hidden="true"><?php _ex( 'To', 'ending hour + minute', 'secupress' ) ?></span>
				<span class="screen-reader-text"><?php _e( 'Hour' ); ?></span>
				<input id="<?php echo $args['name']; ?>_to_hour" name="<?php echo $name_attribute; ?>[to_hour]" value="<?php echo str_pad( $to_hour, 2, 0, STR_PAD_LEFT ); ?>" pattern="0?[0-9]|1[0-9]|2[0-3]"<?php echo $attributes; ?>>
				<span aria-hidden="true"><?php _ex( 'h', 'hour', 'secupress' ); ?></span>
			</label>
			<label>
				<span class="screen-reader-text"><?php _e( 'Minute' ); ?></span>
				<input id="<?php echo $args['name']; ?>_to_minute" name="<?php echo $name_attribute; ?>[to_minute]" value="<?php echo str_pad( $to_minute, 2, 0, STR_PAD_LEFT ); ?>" pattern="0?[0-9]|[1-5][0-9]"<?php echo $attributes; ?>>
				<span aria-hidden="true"><?php _ex( 'min', 'minute', 'secupress' ); ?></span>
			</label>
		</fieldset>
		<?php
	}


	/**
	 * Displays the scheduled backups.
	 *
	 * @since 1.0
	 */
	protected function scheduled_backups() {
		_e( 'None so far.', 'secupress' );
	}


	/**
	 * Displays the scheduled scan.
	 *
	 * @since 1.0
	 */
	protected function scheduled_scan() {
		_e( 'None so far.', 'secupress' );
	}


	/**
	 * Displays the scheduled file monitoring.
	 *
	 * @since 1.0
	 */
	protected function scheduled_monitoring() {
		_e( 'None so far.', 'secupress' );
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
				echo ' <input type="checkbox" id="' . $args['label_for'] . '" name="' . $name_attribute . '" value="1"' . checked( $value, 1, false ) .  $disabled . ' class="secupress-checkbox" /> ';
				echo '<span class="label-text">' . $args['label'] . '</span>';
				echo $label_close;
				?>
			</p>
			<p class="description desc">
				<?php _e( 'Post creation or update will not be logged, but rather password and profile update, email changes, new administrator user, admin has logged in...', 'secupress' ); ?>
			</p>
			<p class="submit"><button type="submit" class="secupress-button secupress-button-primary"><?php esc_html_e( 'Submit' ); ?></button></p>
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
				echo ' <input type="checkbox" id="' . $args['label_for'] . '" name="' . $name_attribute . '" value="1"' . checked( $value, 1, false ) .  $disabled . 'class="secupress-checkbox" /> ';
				echo '<span class="label-text">' . $args['label'] . '</span>';
				?>
			<?php echo $label_close; ?>
			</p>
			<?php echo '<p class="submit"><button type="submit" class="secupress-button secupress-button-primary">' . esc_html__( 'Submit' ) . '</button></p>'; ?>
		</form>
		<?php
	}


	/**
	 * Displays the old backups.
	 *
	 * @since 1.0
	 */
	protected function backup_history() {
		if ( ! secupress_is_pro() ) {
		?>
		<p id="secupress-no-backups"><em><?php _e( 'No Backups found yet, do one?', 'secupress' ); ?></em></p>
		<?php
		} else {
			/**
			 * Fires when SecuPress Pro loads the method backup_history.
			 *
			 * @since 1.0
			 */
	 		do_action( 'secupress.settings.field.backup_history' );
		}
	}


	/**
	 * Displays the tables to launch a backup
	 *
	 * @since 1.0
	 */
	protected function backup_db() {
		if ( ! secupress_is_pro() ) {
		?>
		<p class="submit">
			<button disabled="disabled" class="secupress-button">
				<span class="icon">
					<i class="icon-download"></i>
				</span>
				<span class="text">
					<?php esc_html_e( 'Backup my Database', 'secupress' ); ?>
				</span>
			</button>
		<?php
		} else {
			/**
			 * Fires when SecuPress Pro loads the method backup_db.
			 *
			 * @since 1.0
			 */
	 		do_action( 'secupress.settings.field.backup_db' );
		}
	}


	/**
	 * Displays the files backups and the button to launch one.
	 *
	 * @since 1.0
	 */
	protected function backup_files() {
		if ( ! secupress_is_pro() ) {
		?>
		<p class="submit">
			<button disabled="disabled" class="secupress-button">
				<span class="icon">
					<i class="icon-download"></i>
				</span>
				<span class="text">
					<?php esc_html_e( 'Backup my Files', 'secupress' ); ?>
				</span>
			</button>
		</p>
		<?php
		} else {
			/**
			 * Fires when SecuPress Pro loads the method backup_files.
			 *
			 * @since 1.0
			 */
	 		do_action( 'secupress.settings.field.backup_files' );
		}
	}


	/**
	 * Scan the installation and search for modified/malicious files
	 *
	 * @since 1.0
	 */
	protected function file_scanner() {
		if ( ! secupress_is_pro() ) {
			?>
			<button class="secupress-button disabled" type="button">
				<?php esc_html_e( 'Search for malicious files', 'secupress' ); ?>
			</button>
			<?php
		} else {
			/**
			 * Fires when SecuPress Pro loads the method file_scanner.
			 *
			 * @since 1.0
			 */
	 		do_action( 'secupress.settings.field.file_scanner' );
		}
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
		$plugin_file = SECUPRESS_MODULES_PATH . $this->modulenow . '/settings/' . $plugin . '.php';

		return $this->require_settings_file( $plugin_file, $plugin );
	}
}
