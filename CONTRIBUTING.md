# Contributing

Thanks for being interested in contributing to Anubis!

The project layout is currently fairly straight forward - Anubis uses docopt to parse through the CLI parameters in CLI.py, and uses the comment at the top for any new options or flags. 

It will automatically use the long form of the parameter for any new ones, if provided.

So, for example, to add a new parameter `x` (to be invoked with `anubis -t example.com -x`), we'd change the header definition to add x, like so

```  anubis -t TARGET [-o FILENAME] [-noispbdvx] [-w SCAN]```

And then add the explanation of what it does below, like so

```-x                 sample new command```

If we want a long form, we supply it with two dashes

```-x --example             sample new commmand```

And now to reference it within the code, we'd do `options["--example"]`, which is either True or False, or the contents of the supplied parameter if we're passing something along with the flag.


## Adding new sources

The bulk of the code is in `anubis/commands/target.py`, starting with the `run()` method.

The target URL is in `self.options["TARGET"]`. Feel free to write any additional functions, and then add them to the thread pool in run. 

Your function should not return anything - rather, if it finds any subdomains it should add them to `self.domains`. Make sure it's not been inserted already, and that it's a valid subdomain.

Handle exceptions with `self.handle_exception(e,"stdout message")`

Print to stdout with either `print()` or `ColorPrint.color("message")`

If you have any questions or this is unclear, feel free to open an issue or contact @JonLuca.

## Style

2 spaces for indentation. Follow Google and PEP8 guidelines for the  most part, but I only care as far as it being consistent through the project. 