<?php

/*
 * Render the AppRouter page with a given OPNsense core checkout, the same way
 * ControllerBase does (Phalcon View + Volt + core layout_partials).
 *
 * Catches template incompatibilities like the 26.7 base_dialog change that
 * made the page redirect to the crash reporter.
 *
 * usage: php -d extension=phalcon render.php <plugin src dir> <core src dir>
 * exit code 0 = rendered without errors/warnings and all form fields present
 */

if ($argc !== 3) {
    fwrite(STDERR, "usage: render.php <plugin_src> <core_src>\n");
    exit(2);
}
[, $plugin, $core] = $argv;
$plugin = realpath($plugin);
$core = realpath($core);
$mvc = "$core/opnsense/mvc/app";

// functions normally provided by www/index.php
function view_html_safe($text)
{
    return str_replace("\n", '&#10;', htmlspecialchars($text ?? '', ENT_QUOTES | ENT_HTML401));
}
function view_fetch_themed_filename($url, $theme)
{
    return $url;
}
function view_file_exists($filename)
{
    return file_exists($filename);
}
function view_cache_safe($url)
{
    return $url;
}

require_once "$mvc/library/OPNsense/Autoload/Loader.php";
(new OPNsense\Autoload\Loader(["$mvc/controllers/", "$mvc/models/", "$mvc/library/"]))->register();

$warnings = [];
set_error_handler(function ($no, $msg, $file, $line) use (&$warnings) {
    $warnings[] = "$msg @ " . basename($file) . ":$line";
    return true;
});

$tmp = sys_get_temp_dir() . '/approuter_ui_' . getmypid();
$cleanup = function () use ($tmp) {
    exec('rm -rf ' . escapeshellarg($tmp));
};

$obLevel = ob_get_level();
ob_start();
try {
    // Form parsing through core's own ControllerBase::getForm(). getFormXML()
    // looks for forms/ next to the controller's file, so declare a probe
    // controller in a directory whose forms/ points at the plugin's forms.
    mkdir("$tmp/ctrl", 0700, true);
    symlink("$plugin/opnsense/mvc/app/controllers/OPNsense/Approuter/forms", "$tmp/ctrl/forms");
    file_put_contents("$tmp/ctrl/FormProbe.php", "<?php class FormProbe extends \\OPNsense\\Base\\ControllerBase {}\n");
    require "$tmp/ctrl/FormProbe.php";
    $probe = (new ReflectionClass('FormProbe'))->newInstanceWithoutConstructor();

    $vars = [
        'lang' => new class {
            public function _($text)
            {
                return $text;
            }
        },
        'generalForm' => $probe->getForm('general'),
        'listsForm' => $probe->getForm('lists'),
    ];
    // optional so older plugin revisions can be checked too
    if (file_exists("$tmp/ctrl/forms/dialogRule.xml")) {
        $vars['formDialogRule'] = $probe->getForm('dialogRule');
    }

    // views dir = core partials + plugin view, compiled like ControllerBase does
    mkdir("$tmp/views/OPNsense/Approuter", 0700, true);
    exec('cp -r ' . escapeshellarg("$mvc/views/layout_partials") . ' ' . escapeshellarg("$tmp/views/"));
    copy("$plugin/opnsense/mvc/app/views/OPNsense/Approuter/index.volt", "$tmp/views/OPNsense/Approuter/index.volt");

    $view = new Phalcon\Mvc\View();
    $view->setDI(new Phalcon\Di\FactoryDefault());
    $view->setViewsDir("$tmp/views/");
    $view->registerEngines(['.volt' => function ($v) use ($tmp) {
        $volt = new Phalcon\Mvc\View\Engine\Volt($v);
        $volt->setOptions(['path' => "$tmp/views/", 'separator' => '_', 'always' => true]);
        $volt->getCompiler()->addFunction('theme_file_or_default', 'view_fetch_themed_filename');
        $volt->getCompiler()->addFunction('file_exists', 'view_file_exists');
        $volt->getCompiler()->addFunction('cache_safe', 'view_cache_safe');
        $volt->getCompiler()->addFilter('safe', 'view_html_safe');
        return $volt;
    }]);
    $view->setVars($vars);
    $view->setRenderLevel(Phalcon\Mvc\View::LEVEL_ACTION_VIEW);
    $view->start();
    $view->render('OPNsense/Approuter', 'index');
    $view->finish();
    $html = $view->getContent();
} catch (\Throwable $e) {
    // Phalcon flushes partially rendered output on errors, discard it
    while (ob_get_level() > $obLevel) {
        ob_end_clean();
    }
    $cleanup();
    echo "FAIL: " . get_class($e) . ": " . $e->getMessage() . " @ " . basename($e->getFile()) . ":" . $e->getLine() . "\n";
    exit(1);
}
while (ob_get_level() > $obLevel) {
    ob_end_clean();
}
$cleanup();

$failed = false;
foreach ($warnings as $w) {
    echo "FAIL: PHP warning: $w\n";
    $failed = true;
}
// every field declared in the plugin's form XMLs must be rendered
foreach (glob("$plugin/opnsense/mvc/app/controllers/OPNsense/Approuter/forms/*.xml") as $form) {
    foreach (simplexml_load_file($form)->field as $field) {
        $id = (string)$field->id;
        if (strpos($html, 'id="' . $id . '"') === false) {
            echo "FAIL: field $id (" . basename($form) . ") not rendered\n";
            $failed = true;
        }
    }
}
if ($failed) {
    exit(1);
}
echo "OK: rendered " . strlen($html) . " bytes\n";
