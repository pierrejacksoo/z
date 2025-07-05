import bpy
import bmesh
import numpy as np

def create_sophisticated_hillside(name="SophisticatedHillside", size=24, subdivisions=200, seed=42):
    np.random.seed(seed)
    
    # Create a grid mesh
    bpy.ops.mesh.primitive_grid_add(
        x_subdivisions=subdivisions, 
        y_subdivisions=subdivisions, 
        size=size, 
        location=(0, 0, 0)
    )
    obj = bpy.context.active_object
    mesh = obj.data

    bm = bmesh.new()
    bm.from_mesh(mesh)

    # More sophisticated hillside: layered undulations, "terraces", valleys, and varied steepness
    for v in bm.verts:
        x, y = v.co.x, v.co.y

        # Main slope (steeper in some parts)
        base_slope = (x * 0.44) + (y * 0.09)
        slope_mod = 0.25 * np.tanh((x+6)/6) * np.cos(0.13*y)

        # Layered terraces (gentle step-like features)
        terraces = 0.34 * np.sin(0.33*x + 0.45*y + seed/2)**3

        # Broad undulations (large, smooth hills and dips)
        big_hills = (
            2.8 * np.exp(-((x-4)**2/77 + (y+7)**2/170)) +
            1.7 * np.exp(-((x+6)**2/110 + (y-7)**2/143)) +
            0.7 * np.exp(-((x-10)**2/250 + (y-2)**2/140))
        )

        # Valley features (gentle dips, inspired by natural erosion)
        valleys = -0.7 * np.exp(-((x+9)**2/115 + (y-6)**2/70))
        
        # Ridge/crest line (a line of higher elevation, inspired by reference)
        ridge = 0.8 * np.exp(-((x-0.5*y)**2/100 + (y-4)**2/340))

        # Natural gentle noise, but a bit more varied
        gentle_noise = (
            0.15 * np.sin(0.13*x + 0.19*y + seed) +
            0.10 * np.cos(0.08*x - 0.16*y + seed*2)
        )

        # Composite height
        v.co.z = (
            base_slope + slope_mod +
            terraces +
            big_hills +
            valleys +
            ridge +
            gentle_noise
        )

    bm.to_mesh(mesh)
    bm.free()

    # Optional: Subsurf for extra smoothness
    subsurf = obj.modifiers.new(name='Subdivision', type='SUBSURF')
    subsurf.levels = 2
    subsurf.render_levels = 3

    # Shade smooth
    bpy.ops.object.shade_smooth()
    obj.name = name

    # Add a grassy material
    mat = bpy.data.materials.new(name="GrassyHillside")
    mat.use_nodes = True
    nodes = mat.node_tree.nodes
    links = mat.node_tree.links

    # Clear default nodes
    for n in nodes:
        nodes.remove(n)
    output = nodes.new(type="ShaderNodeOutputMaterial")
    diffuse = nodes.new(type="ShaderNodeBsdfDiffuse")
    colorramp = nodes.new(type="ShaderNodeValToRGB")
    geometry = nodes.new(type="ShaderNodeNewGeometry")

    # Grass color ramp (deeper shades for more variety)
    colorramp.color_ramp.elements.new(0.4)
    colorramp.color_ramp.elements.new(0.7)
    colorramp.color_ramp.elements[0].color = (0.27, 0.36, 0.16, 1)
    colorramp.color_ramp.elements[1].color = (0.40, 0.56, 0.19, 1)
    colorramp.color_ramp.elements[2].color = (0.52, 0.64, 0.28, 1)
    colorramp.color_ramp.elements[3].color = (0.67, 0.73, 0.38, 1)

    links.new(geometry.outputs['Normal'], colorramp.inputs['Fac'])
    links.new(colorramp.outputs['Color'], diffuse.inputs['Color'])
    links.new(diffuse.outputs['BSDF'], output.inputs['Surface'])

    obj.data.materials.append(mat)

# Remove all objects
bpy.ops.object.select_all(action='SELECT')
bpy.ops.object.delete(use_global=False)

# Create the sophisticated grassy hillside
create_sophisticated_hillside()
