# virut_disinfection
A python script for disinfecting the PE files wich were infected by one version of Virut file infector.

# Folders

	+ src: You can find the code.
	+ bin: You can find some infected binaries. 
	       ¡BE CAREFUL! If you want to execute these samples, do it in a sandbox.

# Usage

Usage:

      1) python src/disinfector.py path_to_the_infected_pe
      2) python src/disinfector.py path_to_the_infected_pe output_filename

Example:

      1) python src/disinfector.py explorer.exe
      2) python src/disinfector.py explorer.exe explorer_disinfected.exe

Output:

      If the function succeeds, the return value is a disinfected file with .disinfected extension
      or with the given output filename

# Disinfect a directory

	You can import src/disinfector.py as a module to another python script. There is a function in the src/disinfector.py script "disinfect_directory(path)" wich you can use for disinfect a directory. Just pass to the function the path of the directory that you want to disinfect.

