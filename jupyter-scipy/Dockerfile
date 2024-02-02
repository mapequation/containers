FROM jupyter/scipy-notebook

# Install Python 3 packages
RUN mamba install --yes \
    'networkx' && \
    mamba clean --all -f -y && \
    fix-permissions "${CONDA_DIR}" && \
    fix-permissions "/home/${NB_USER}"