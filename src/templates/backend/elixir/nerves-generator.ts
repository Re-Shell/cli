import { ElixirBackendGenerator } from './elixir-base-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export class NervesGenerator extends ElixirBackendGenerator {
  getFrameworkDependencies(): any[] {
    return [
      {name: "nerves", version: "~> 1.10"},
      {name: "nerves_runtime", version: "~> 0.13"},
      {name: "nerves_pack", version: "~> 0.7"},
      {name: "nerves_time", version: "~> 0.4"},
      {name: "nerves_init_gadget", version: "~> 0.8"},
      {name: "nerves_firmware_ssh", version: "~> 0.4"},
      {name: "nerves_hub_link", version: "~> 2.2"},
      {name: "phoenix_pubsub", version: "~> 2.1"},
      {name: "jason", version: "~> 1.4"},
      {name: "circuits_gpio", version: "~> 1.0"},
      {name: "circuits_i2c", version: "~> 1.0"},
      {name: "circuits_spi", version: "~> 1.0"},
      {name: "circuits_uart", version: "~> 1.0"},
      {name: "vintage_net", version: "~> 0.13"},
      {name: "vintage_net_wifi", version: "~> 0.12"},
      {name: "vintage_net_ethernet", version: "~> 0.11"},
      {name: "mdns_lite", version: "~> 0.8"},
      {name: "telemetry", version: "~> 1.2"},
      {name: "telemetry_metrics", version: "~> 0.6"},
      {name: "telemetry_poller", version: "~> 1.0"},
      {name: "ex_doc", version: "~> 0.27", only: "dev", runtime: false},
      {name: "dialyxir", version: "~> 1.3", only: ["dev"], runtime: false},
      {name: "credo", version: "~> 1.7", only: ["dev", "test"], runtime: false}
    ];
  }

  generateMainApplicationFile(): string {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Application do
  @moduledoc false

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    # Configure MDNs for device discovery
    setup_mdns()

    children = [
      # Phoenix PubSub for inter-process communication
      {Phoenix.PubSub, name: ${moduleName}.PubSub},
      
      # Telemetry supervisor
      ${moduleName}.Telemetry,
      
      # Device supervisor for hardware management
      ${moduleName}.DeviceSupervisor,
      
      # Sensor supervisor for data collection
      ${moduleName}.SensorSupervisor,
      
      # Network manager
      ${moduleName}.NetworkManager,
      
      # Firmware update manager
      ${moduleName}.FirmwareManager,
      
      # State synchronization
      ${moduleName}.StateSync,
      
      # Hardware abstraction layer
      ${moduleName}.HAL.Supervisor
    ]

    opts = [strategy: :one_for_one, name: ${moduleName}.Supervisor]
    
    Logger.info("[${moduleName}] Starting Nerves application on \#{target()}")
    Supervisor.start_link(children, opts)
  end

  @impl true
  def stop(_state) do
    Logger.info("[${moduleName}] Stopping Nerves application...")
    :ok
  end

  defp setup_mdns() do
    mdns_config = %{
      services: [
        %{
          protocol: "http",
          transport: "tcp",
          port: 80
        },
        %{
          name: "${appName}",
          protocol: "ssh",
          transport: "tcp",
          port: 22
        }
      ]
    }

    MdnsLite.set_config(mdns_config)
  end

  def target() do
    Application.get_env(:${appName}, :target)
  end
end
`;
  }

  generateSupervisorFile(): string {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.DeviceSupervisor do
  @moduledoc """
  Supervisor for hardware device management.
  """
  use Supervisor
  require Logger

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    children = [
      # GPIO controller
      {${moduleName}.HAL.GPIOController, []},
      
      # I2C bus manager
      {${moduleName}.HAL.I2CManager, []},
      
      # SPI device manager
      {${moduleName}.HAL.SPIManager, []},
      
      # UART serial communication
      {${moduleName}.HAL.UARTManager, []},
      
      # LED controller
      {${moduleName}.Devices.LEDController, []},
      
      # Button handler
      {${moduleName}.Devices.ButtonHandler, []},
      
      # Device registry
      {${moduleName}.DeviceRegistry, []}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end

defmodule ${moduleName}.SensorSupervisor do
  @moduledoc """
  Supervisor for sensor data collection and processing.
  """
  use Supervisor
  require Logger

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    children = [
      # Temperature sensor
      {${moduleName}.Sensors.Temperature, []},
      
      # Humidity sensor
      {${moduleName}.Sensors.Humidity, []},
      
      # Motion detector
      {${moduleName}.Sensors.Motion, []},
      
      # Light sensor
      {${moduleName}.Sensors.Light, []},
      
      # Sensor data aggregator
      {${moduleName}.Sensors.DataAggregator, []},
      
      # Sensor telemetry
      {${moduleName}.Sensors.Telemetry, []}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
`;
  }

  generateGenServerFiles(): { path: string; content: string }[] {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return [
      {
        path: `lib/${appName}/hal/gpio_controller.ex`,
        content: `defmodule ${moduleName}.HAL.GPIOController do
  @moduledoc """
  Hardware abstraction layer for GPIO control.
  """
  use GenServer
  alias Circuits.GPIO
  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(_opts) do
    state = %{
      pins: %{},
      interrupts: %{}
    }
    
    {:ok, state}
  end

  # Public API

  def open_pin(pin_number, direction, opts \\\\ []) do
    GenServer.call(__MODULE__, {:open_pin, pin_number, direction, opts})
  end

  def write(pin_number, value) do
    GenServer.call(__MODULE__, {:write, pin_number, value})
  end

  def read(pin_number) do
    GenServer.call(__MODULE__, {:read, pin_number})
  end

  def set_interrupts(pin_number, trigger, opts \\\\ []) do
    GenServer.call(__MODULE__, {:set_interrupts, pin_number, trigger, opts})
  end

  # Callbacks

  def handle_call({:open_pin, pin_number, direction, opts}, _from, state) do
    case GPIO.open(pin_number, direction, opts) do
      {:ok, ref} ->
        new_state = put_in(state.pins[pin_number], ref)
        {:reply, {:ok, ref}, new_state}
      
      {:error, reason} = error ->
        Logger.error("[GPIO] Failed to open pin #{pin_number}: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  def handle_call({:write, pin_number, value}, _from, state) do
    case Map.get(state.pins, pin_number) do
      nil ->
        {:reply, {:error, :pin_not_open}, state}
      
      ref ->
        result = GPIO.write(ref, value)
        {:reply, result, state}
    end
  end

  def handle_call({:read, pin_number}, _from, state) do
    case Map.get(state.pins, pin_number) do
      nil ->
        {:reply, {:error, :pin_not_open}, state}
      
      ref ->
        value = GPIO.read(ref)
        {:reply, {:ok, value}, state}
    end
  end

  def handle_call({:set_interrupts, pin_number, trigger, opts}, _from, state) do
    case Map.get(state.pins, pin_number) do
      nil ->
        {:reply, {:error, :pin_not_open}, state}
      
      ref ->
        result = GPIO.set_interrupts(ref, trigger, opts)
        {:reply, result, state}
    end
  end

  def handle_info({:circuits_gpio, pin_number, _timestamp, value}, state) do
    Logger.debug("[GPIO] Interrupt on pin #{pin_number}: #{value}")
    # Broadcast GPIO interrupt event
    Phoenix.PubSub.broadcast(
      ${moduleName}.PubSub,
      "gpio:interrupts",
      {:gpio_interrupt, pin_number, value}
    )
    {:noreply, state}
  end
end
`
      },
      {
        path: `lib/${appName}/devices/led_controller.ex`,
        content: `defmodule ${moduleName}.Devices.LEDController do
  @moduledoc """
  LED control with patterns and effects.
  """
  use GenServer
  alias ${moduleName}.HAL.GPIOController
  require Logger

  @default_led_pin 18  # GPIO18 - adjust for your hardware

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(opts) do
    led_pin = Keyword.get(opts, :pin, @default_led_pin)
    
    # Open GPIO pin for LED
    {:ok, _ref} = GPIOController.open_pin(led_pin, :output)
    
    state = %{
      pin: led_pin,
      pattern: :off,
      timer_ref: nil
    }
    
    {:ok, state}
  end

  # Public API

  def on() do
    GenServer.cast(__MODULE__, :on)
  end

  def off() do
    GenServer.cast(__MODULE__, :off)
  end

  def blink(interval_ms \\\\ 500) do
    GenServer.cast(__MODULE__, {:blink, interval_ms})
  end

  def pattern(pattern_name) do
    GenServer.cast(__MODULE__, {:pattern, pattern_name})
  end

  # Callbacks

  def handle_cast(:on, state) do
    GPIOController.write(state.pin, 1)
    state = cancel_timer(state)
    {:noreply, %{state | pattern: :on}}
  end

  def handle_cast(:off, state) do
    GPIOController.write(state.pin, 0)
    state = cancel_timer(state)
    {:noreply, %{state | pattern: :off}}
  end

  def handle_cast({:blink, interval}, state) do
    state = cancel_timer(state)
    timer_ref = Process.send_after(self(), :toggle, interval)
    {:noreply, %{state | pattern: {:blink, interval}, timer_ref: timer_ref}}
  end

  def handle_cast({:pattern, :heartbeat}, state) do
    state = cancel_timer(state)
    send(self(), {:heartbeat, 0})
    {:noreply, %{state | pattern: :heartbeat}}
  end

  def handle_cast({:pattern, :sos}, state) do
    state = cancel_timer(state)
    send(self(), {:sos, 0})
    {:noreply, %{state | pattern: :sos}}
  end

  def handle_info(:toggle, %{pattern: {:blink, interval}} = state) do
    {:ok, current} = GPIOController.read(state.pin)
    GPIOController.write(state.pin, 1 - current)
    timer_ref = Process.send_after(self(), :toggle, interval)
    {:noreply, %{state | timer_ref: timer_ref}}
  end

  def handle_info({:heartbeat, step}, state) do
    # Heartbeat pattern: quick double flash
    pattern = [1, 0, 1, 0, 0, 0, 0, 0]
    value = Enum.at(pattern, rem(step, length(pattern)))
    GPIOController.write(state.pin, value)
    
    timer_ref = Process.send_after(self(), {:heartbeat, step + 1}, 100)
    {:noreply, %{state | timer_ref: timer_ref}}
  end

  def handle_info({:sos, step}, state) do
    # SOS pattern in Morse code
    pattern = [
      1, 0, 1, 0, 1, 0, 0, 0,  # S (...)
      1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0,  # O (---)
      1, 0, 1, 0, 1, 0, 0, 0   # S (...)
    ]
    
    value = Enum.at(pattern, rem(step, length(pattern)))
    GPIOController.write(state.pin, value)
    
    timer_ref = Process.send_after(self(), {:sos, step + 1}, 200)
    {:noreply, %{state | timer_ref: timer_ref}}
  end

  defp cancel_timer(%{timer_ref: nil} = state), do: state
  defp cancel_timer(%{timer_ref: ref} = state) do
    Process.cancel_timer(ref)
    %{state | timer_ref: nil}
  end
end
`
      },
      {
        path: `lib/${appName}/sensors/temperature.ex`,
        content: `defmodule ${moduleName}.Sensors.Temperature do
  @moduledoc """
  Temperature sensor reading and monitoring.
  """
  use GenServer
  require Logger

  @read_interval 5_000  # Read every 5 seconds

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(opts) do
    sensor_type = Keyword.get(opts, :sensor_type, :mock)
    
    state = %{
      sensor_type: sensor_type,
      last_reading: nil,
      readings: [],
      max_readings: 100
    }
    
    # Schedule first reading
    Process.send_after(self(), :read_temperature, 1000)
    
    {:ok, state}
  end

  # Public API

  def get_current() do
    GenServer.call(__MODULE__, :get_current)
  end

  def get_average(minutes \\\\ 5) do
    GenServer.call(__MODULE__, {:get_average, minutes})
  end

  def get_history() do
    GenServer.call(__MODULE__, :get_history)
  end

  # Callbacks

  def handle_call(:get_current, _from, state) do
    {:reply, state.last_reading, state}
  end

  def handle_call({:get_average, minutes}, _from, state) do
    cutoff = DateTime.utc_now() |> DateTime.add(-minutes * 60, :second)
    
    average = 
      state.readings
      |> Enum.filter(fn {timestamp, _} -> DateTime.compare(timestamp, cutoff) == :gt end)
      |> Enum.map(fn {_, temp} -> temp end)
      |> average()
    
    {:reply, average, state}
  end

  def handle_call(:get_history, _from, state) do
    {:reply, state.readings, state}
  end

  def handle_info(:read_temperature, state) do
    # Read temperature based on sensor type
    temperature = read_sensor(state.sensor_type)
    timestamp = DateTime.utc_now()
    
    # Update state with new reading
    reading = {timestamp, temperature}
    readings = [{timestamp, temperature} | state.readings] |> Enum.take(state.max_readings)
    
    # Publish temperature event
    Phoenix.PubSub.broadcast(
      ${moduleName}.PubSub,
      "sensors:temperature",
      {:temperature_reading, temperature, timestamp}
    )
    
    # Log if temperature is out of range
    check_temperature_threshold(temperature)
    
    # Schedule next reading
    Process.send_after(self(), :read_temperature, @read_interval)
    
    {:noreply, %{state | last_reading: reading, readings: readings}}
  end

  defp read_sensor(:mock) do
    # Simulate temperature readings
    base_temp = 22.0
    variation = :rand.uniform() * 4.0 - 2.0
    Float.round(base_temp + variation, 1)
  end

  defp read_sensor(:dht22) do
    # Read from DHT22 sensor
    # This would use a library like dht
    case read_dht22_sensor() do
      {:ok, temp, _humidity} -> temp
      {:error, _} -> nil
    end
  end

  defp read_sensor(:ds18b20) do
    # Read from DS18B20 1-wire sensor
    # This would read from /sys/bus/w1/devices/
    case read_onewire_sensor() do
      {:ok, temp} -> temp
      {:error, _} -> nil
    end
  end

  defp read_dht22_sensor() do
    # Placeholder for actual DHT22 reading
    {:ok, 23.5, 45.0}
  end

  defp read_onewire_sensor() do
    # Placeholder for actual 1-wire reading
    {:ok, 23.5}
  end

  defp check_temperature_threshold(temperature) when is_number(temperature) do
    cond do
      temperature > 30.0 ->
        Logger.warn("[Temperature] High temperature alert: #{temperature}°C")
      
      temperature < 10.0 ->
        Logger.warn("[Temperature] Low temperature alert: #{temperature}°C")
      
      true ->
        :ok
    end
  end

  defp check_temperature_threshold(_), do: :ok

  defp average([]), do: nil
  defp average(numbers) do
    Enum.sum(numbers) / length(numbers)
  end
end
`
      },
      {
        path: `lib/${appName}/network_manager.ex`,
        content: `defmodule ${moduleName}.NetworkManager do
  @moduledoc """
  Network configuration and management using VintageNet.
  """
  use GenServer
  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(_opts) do
    # Subscribe to network events
    VintageNet.subscribe(["interface", "wlan0"])
    VintageNet.subscribe(["interface", "eth0"])
    
    state = %{
      current_interface: nil,
      wifi_configured: false
    }
    
    # Configure network on startup
    configure_network()
    
    {:ok, state}
  end

  # Public API

  def get_status() do
    GenServer.call(__MODULE__, :get_status)
  end

  def configure_wifi(ssid, passphrase) do
    GenServer.call(__MODULE__, {:configure_wifi, ssid, passphrase})
  end

  def configure_ethernet() do
    GenServer.call(__MODULE__, :configure_ethernet)
  end

  # Callbacks

  def handle_call(:get_status, _from, state) do
    status = %{
      interfaces: VintageNet.all_interfaces(),
      current: state.current_interface,
      ip_addresses: get_all_ip_addresses(),
      wifi_configured: state.wifi_configured
    }
    
    {:reply, status, state}
  end

  def handle_call({:configure_wifi, ssid, passphrase}, _from, state) do
    config = %{
      type: VintageNetWiFi,
      vintage_net_wifi: %{
        networks: [
          %{
            key_mgmt: :wpa_psk,
            ssid: ssid,
            psk: passphrase
          }
        ]
      },
      ipv4: %{method: :dhcp}
    }
    
    case VintageNet.configure("wlan0", config) do
      :ok ->
        Logger.info("[Network] WiFi configured for SSID: #{ssid}")
        {:reply, :ok, %{state | wifi_configured: true}}
      
      {:error, reason} = error ->
        Logger.error("[Network] Failed to configure WiFi: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  def handle_call(:configure_ethernet, _from, state) do
    config = %{
      type: VintageNetEthernet,
      ipv4: %{method: :dhcp}
    }
    
    case VintageNet.configure("eth0", config) do
      :ok ->
        Logger.info("[Network] Ethernet configured for DHCP")
        {:reply, :ok, state}
      
      {:error, reason} = error ->
        Logger.error("[Network] Failed to configure Ethernet: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  def handle_info({VintageNet, ["interface", interface, "connection"], _old, :internet, _meta}, state) do
    Logger.info("[Network] #{interface} connected to internet")
    
    # Notify other processes about connectivity
    Phoenix.PubSub.broadcast(
      ${moduleName}.PubSub,
      "network:status",
      {:network_connected, interface}
    )
    
    {:noreply, %{state | current_interface: interface}}
  end

  def handle_info({VintageNet, ["interface", interface, "connection"], _old, :disconnected, _meta}, state) do
    Logger.warn("[Network] #{interface} disconnected")
    
    Phoenix.PubSub.broadcast(
      ${moduleName}.PubSub,
      "network:status",
      {:network_disconnected, interface}
    )
    
    new_interface = if state.current_interface == interface, do: nil, else: state.current_interface
    {:noreply, %{state | current_interface: new_interface}}
  end

  def handle_info({VintageNet, _path, _old, _new, _meta}, state) do
    # Ignore other VintageNet events
    {:noreply, state}
  end

  defp configure_network() do
    # Try Ethernet first
    configure_ethernet()
    
    # If WiFi credentials are available in config, configure WiFi
    case Application.get_env(:${appName}, :wifi) do
      %{ssid: ssid, psk: psk} when is_binary(ssid) and is_binary(psk) ->
        configure_wifi(ssid, psk)
      
      _ ->
        Logger.info("[Network] No WiFi credentials configured")
    end
  end

  defp get_all_ip_addresses() do
    VintageNet.all_interfaces()
    |> Enum.map(fn interface ->
      addresses = VintageNet.get(["interface", interface, "addresses"], [])
      {interface, addresses}
    end)
    |> Enum.into(%{})
  end
end
`
      },
      {
        path: `lib/${appName}/firmware_manager.ex`,
        content: `defmodule ${moduleName}.FirmwareManager do
  @moduledoc """
  Firmware update management with NervesHub integration.
  """
  use GenServer
  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(_opts) do
    # Subscribe to firmware update events
    Phoenix.PubSub.subscribe(${moduleName}.PubSub, "firmware:updates")
    
    state = %{
      current_version: current_firmware_version(),
      update_in_progress: false,
      last_check: nil
    }
    
    # Schedule periodic update checks
    schedule_update_check()
    
    {:ok, state}
  end

  # Public API

  def get_status() do
    GenServer.call(__MODULE__, :get_status)
  end

  def check_for_updates() do
    GenServer.cast(__MODULE__, :check_updates)
  end

  def apply_update(url) do
    GenServer.call(__MODULE__, {:apply_update, url})
  end

  # Callbacks

  def handle_call(:get_status, _from, state) do
    {:reply, state, state}
  end

  def handle_call({:apply_update, url}, _from, %{update_in_progress: true} = state) do
    {:reply, {:error, :update_in_progress}, state}
  end

  def handle_call({:apply_update, url}, _from, state) do
    Logger.info("[Firmware] Starting firmware update from: #{url}")
    
    case download_and_apply_firmware(url) do
      :ok ->
        {:reply, :ok, %{state | update_in_progress: true}}
      
      {:error, reason} = error ->
        Logger.error("[Firmware] Update failed: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  def handle_cast(:check_updates, state) do
    # Check NervesHub for updates
    case NervesHubLink.check_update() do
      :ok ->
        Logger.info("[Firmware] Update check initiated")
        {:noreply, %{state | last_check: DateTime.utc_now()}}
      
      {:error, reason} ->
        Logger.error("[Firmware] Update check failed: #{inspect(reason)}")
        {:noreply, state}
    end
  end

  def handle_info(:check_for_updates, state) do
    check_for_updates()
    schedule_update_check()
    {:noreply, state}
  end

  def handle_info({:nerves_hub, :update_available, %{version: version}}, state) do
    Logger.info("[Firmware] Update available: #{version}")
    
    Phoenix.PubSub.broadcast(
      ${moduleName}.PubSub,
      "firmware:notifications",
      {:firmware_update_available, version}
    )
    
    {:noreply, state}
  end

  def handle_info({:nerves_hub, :update_applied}, state) do
    Logger.info("[Firmware] Update applied successfully, rebooting...")
    
    # The system will reboot automatically
    {:noreply, %{state | update_in_progress: false}}
  end

  defp current_firmware_version() do
    Application.get_env(:nerves_runtime, :firmware_version, "unknown")
  end

  defp schedule_update_check() do
    # Check every 6 hours
    Process.send_after(self(), :check_for_updates, 6 * 60 * 60 * 1000)
  end

  defp download_and_apply_firmware(url) do
    # This would integrate with Nerves.Runtime.KV
    # and handle the actual firmware update process
    :ok
  end
end
`
      }
    ];
  }

  generateRouterFile(): string {
    // Nerves doesn't typically use web routers, but we can provide a simple HTTP interface
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.HTTPInterface do
  @moduledoc """
  Simple HTTP interface for device status and control.
  Not a full web framework - just basic device API.
  """
  use Plug.Router
  alias ${moduleName}.{DeviceRegistry, Sensors, Devices, NetworkManager, FirmwareManager}

  plug :match
  plug Plug.Parsers,
    parsers: [:json],
    pass: ["application/json"],
    json_decoder: Jason
  plug :dispatch

  # Device status
  get "/status" do
    status = %{
      device: %{
        name: "${appName}",
        version: Application.spec(:${appName}, :vsn),
        uptime: get_uptime()
      },
      network: NetworkManager.get_status(),
      firmware: FirmwareManager.get_status(),
      sensors: get_sensor_readings()
    }
    
    send_json(conn, 200, status)
  end

  # Sensor readings
  get "/sensors" do
    readings = get_sensor_readings()
    send_json(conn, 200, readings)
  end

  get "/sensors/:type" do
    case get_sensor_reading(type) do
      {:ok, reading} ->
        send_json(conn, 200, reading)
      
      {:error, :not_found} ->
        send_json(conn, 404, %{error: "Sensor not found"})
    end
  end

  # LED control
  post "/led/:action" do
    case action do
      "on" ->
        Devices.LEDController.on()
        send_json(conn, 200, %{status: "LED on"})
      
      "off" ->
        Devices.LEDController.off()
        send_json(conn, 200, %{status: "LED off"})
      
      "blink" ->
        Devices.LEDController.blink()
        send_json(conn, 200, %{status: "LED blinking"})
      
      _ ->
        send_json(conn, 400, %{error: "Invalid action"})
    end
  end

  # Network configuration
  post "/network/wifi" do
    with %{"ssid" => ssid, "passphrase" => passphrase} <- conn.body_params,
         :ok <- NetworkManager.configure_wifi(ssid, passphrase) do
      send_json(conn, 200, %{status: "WiFi configured"})
    else
      _ ->
        send_json(conn, 400, %{error: "Invalid WiFi configuration"})
    end
  end

  # Firmware updates
  post "/firmware/check" do
    FirmwareManager.check_for_updates()
    send_json(conn, 200, %{status: "Update check initiated"})
  end

  # Catch-all
  match _ do
    send_json(conn, 404, %{error: "Not found"})
  end

  defp send_json(conn, status, data) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(data))
  end

  defp get_uptime() do
    {uptime, _} = :erlang.statistics(:wall_clock)
    uptime
  end

  defp get_sensor_readings() do
    %{
      temperature: Sensors.Temperature.get_current(),
      humidity: get_mock_reading("humidity", 45.0, 5.0),
      motion: get_mock_reading("motion", 0, 1, :boolean),
      light: get_mock_reading("light", 500, 100)
    }
  end

  defp get_sensor_reading("temperature") do
    {:ok, Sensors.Temperature.get_current()}
  end

  defp get_sensor_reading(_), do: {:error, :not_found}

  defp get_mock_reading(type, base, variation, mode \\\\ :float) do
    value = case mode do
      :float -> base + (:rand.uniform() * variation * 2 - variation)
      :boolean -> :rand.uniform(2) - 1
      _ -> base
    end
    
    %{
      type: type,
      value: value,
      timestamp: DateTime.utc_now()
    }
  end
end
`;
  }

  generateControllerFiles(): { path: string; content: string }[] {
    // Nerves doesn't use traditional controllers
    return [];
  }

  generateServiceFiles(): { path: string; content: string }[] {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return [
      {
        path: `lib/${appName}/device_registry.ex`,
        content: `defmodule ${moduleName}.DeviceRegistry do
  @moduledoc """
  Registry for connected devices and peripherals.
  """
  use GenServer
  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(_opts) do
    state = %{
      devices: %{},
      device_types: %{}
    }
    
    {:ok, state}
  end

  # Public API

  def register_device(device_id, type, config) do
    GenServer.call(__MODULE__, {:register, device_id, type, config})
  end

  def unregister_device(device_id) do
    GenServer.call(__MODULE__, {:unregister, device_id})
  end

  def get_device(device_id) do
    GenServer.call(__MODULE__, {:get_device, device_id})
  end

  def list_devices(type \\\\ nil) do
    GenServer.call(__MODULE__, {:list_devices, type})
  end

  # Callbacks

  def handle_call({:register, device_id, type, config}, _from, state) do
    device = %{
      id: device_id,
      type: type,
      config: config,
      registered_at: DateTime.utc_now(),
      status: :active
    }
    
    new_state = 
      state
      |> put_in([:devices, device_id], device)
      |> update_in([:device_types, type], fn
        nil -> [device_id]
        list -> [device_id | list] |> Enum.uniq()
      end)
    
    Logger.info("[DeviceRegistry] Registered device: #{device_id} (#{type})")
    
    {:reply, :ok, new_state}
  end

  def handle_call({:unregister, device_id}, _from, state) do
    case get_in(state, [:devices, device_id]) do
      nil ->
        {:reply, {:error, :not_found}, state}
      
      device ->
        new_state = 
          state
          |> update_in([:devices], &Map.delete(&1, device_id))
          |> update_in([:device_types, device.type], &List.delete(&1, device_id))
        
        Logger.info("[DeviceRegistry] Unregistered device: #{device_id}")
        
        {:reply, :ok, new_state}
    end
  end

  def handle_call({:get_device, device_id}, _from, state) do
    device = get_in(state, [:devices, device_id])
    {:reply, device, state}
  end

  def handle_call({:list_devices, nil}, _from, state) do
    devices = Map.values(state.devices)
    {:reply, devices, state}
  end

  def handle_call({:list_devices, type}, _from, state) do
    device_ids = get_in(state, [:device_types, type]) || []
    devices = Enum.map(device_ids, &state.devices[&1])
    {:reply, devices, state}
  end
end
`
      },
      {
        path: `lib/${appName}/state_sync.ex`,
        content: `defmodule ${moduleName}.StateSync do
  @moduledoc """
  State synchronization between device and cloud/server.
  """
  use GenServer
  require Logger

  @sync_interval 30_000  # Sync every 30 seconds

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(_opts) do
    state = %{
      local_state: %{},
      last_sync: nil,
      pending_changes: [],
      sync_enabled: true
    }
    
    # Schedule first sync
    schedule_sync()
    
    # Subscribe to state change events
    Phoenix.PubSub.subscribe(${moduleName}.PubSub, "state:changes")
    
    {:ok, state}
  end

  # Public API

  def update_state(key, value) do
    GenServer.cast(__MODULE__, {:update_state, key, value})
  end

  def get_state(key \\\\ nil) do
    GenServer.call(__MODULE__, {:get_state, key})
  end

  def sync_now() do
    GenServer.cast(__MODULE__, :sync_now)
  end

  def enable_sync(enabled) do
    GenServer.cast(__MODULE__, {:enable_sync, enabled})
  end

  # Callbacks

  def handle_cast({:update_state, key, value}, state) do
    change = %{
      key: key,
      value: value,
      timestamp: DateTime.utc_now(),
      synced: false
    }
    
    new_state = 
      state
      |> put_in([:local_state, key], value)
      |> update_in([:pending_changes], &[change | &1])
    
    # Broadcast state change
    Phoenix.PubSub.broadcast(
      ${moduleName}.PubSub,
      "state:updates",
      {:state_updated, key, value}
    )
    
    {:noreply, new_state}
  end

  def handle_cast(:sync_now, %{sync_enabled: false} = state) do
    Logger.debug("[StateSync] Sync disabled, skipping")
    {:noreply, state}
  end

  def handle_cast(:sync_now, state) do
    new_state = perform_sync(state)
    {:noreply, new_state}
  end

  def handle_cast({:enable_sync, enabled}, state) do
    Logger.info("[StateSync] Sync #{if enabled, do: "enabled", else: "disabled"}")
    {:noreply, %{state | sync_enabled: enabled}}
  end

  def handle_call({:get_state, nil}, _from, state) do
    {:reply, state.local_state, state}
  end

  def handle_call({:get_state, key}, _from, state) do
    value = get_in(state, [:local_state, key])
    {:reply, value, state}
  end

  def handle_info(:sync, %{sync_enabled: false} = state) do
    schedule_sync()
    {:noreply, state}
  end

  def handle_info(:sync, state) do
    new_state = perform_sync(state)
    schedule_sync()
    {:noreply, new_state}
  end

  defp perform_sync(state) do
    case sync_with_server(state.local_state, state.pending_changes) do
      {:ok, synced_changes} ->
        Logger.info("[StateSync] Synced #{length(synced_changes)} changes")
        
        # Mark changes as synced
        pending = Enum.reject(state.pending_changes, fn change ->
          Enum.any?(synced_changes, &(&1.key == change.key))
        end)
        
        %{state | 
          pending_changes: pending,
          last_sync: DateTime.utc_now()
        }
      
      {:error, reason} ->
        Logger.error("[StateSync] Sync failed: #{inspect(reason)}")
        state
    end
  end

  defp sync_with_server(_state, changes) do
    # This would implement actual sync with a server
    # For now, simulate successful sync
    {:ok, changes}
  end

  defp schedule_sync() do
    Process.send_after(self(), :sync, @sync_interval)
  end
end
`
      }
    ];
  }

  generateConfigFiles(): { path: string; content: string }[] {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return [
      {
        path: `config/config.exs`,
        content: `import Config

# Configuration for ${appName} Nerves application

config :${appName}, target: Mix.target()

# Customize non-Elixir parts of the firmware
config :nerves, :firmware, rootfs_overlay: "rootfs_overlay"

# Use shoehorn to start the main application
config :shoehorn,
  init: [:nerves_runtime, :nerves_pack],
  app: Mix.Project.config()[:app]

# Configure nerves_runtime
config :nerves_runtime, :kernel, use_system_registry: false

# Configure logger
config :logger, backends: [RingLogger]

# Configure Phoenix PubSub
config :${appName}, ${moduleName}.PubSub,
  name: ${moduleName}.PubSub,
  adapter: Phoenix.PubSub.PG2

# Import target specific config
if Mix.target() != :host do
  import_config "target.exs"
end

# Import environment specific config
import_config "#{Mix.env()}.exs"
`
      },
      {
        path: `config/host.exs`,
        content: `import Config

# Configuration for running on host (development machine)

# Configure network for host testing
config :vintage_net,
  regulatory_domain: "US",
  config: [
    {"eth0", %{type: VintageNetEthernet, ipv4: %{method: :dhcp}}},
    {"wlan0", %{type: VintageNetWiFi}}
  ]

# Mock hardware for host testing
config :${appName},
  mock_hardware: true,
  led_pin: nil

# Use erl_exec for port process management on host
config :nerves_runtime, 
  revert: false

# Configure database for host
config :${appName}, ${moduleName}.Repo,
  database: Path.expand("../.sqlite/\#{Mix.env()}.db", __DIR__),
  pool_size: 5,
  show_sensitive_data_on_connection_error: true
`
      },
      {
        path: `config/target.exs`,
        content: `import Config

# Configuration for all targets except host

# Nerves Runtime can enumerate hardware devices
config :nerves_runtime, :kernel, use_system_registry: false

# Authorize the device to receive firmware using NervesHub
config :nerves_hub_link,
  configurator: NervesHubLink.Configurator

config :nerves_ssh,
  authorized_keys: [
    File.read!(Path.join(System.user_home!(), ".ssh/id_rsa.pub"))
  ]

# Configure network
config :vintage_net,
  regulatory_domain: "US",
  config: [
    {"usb0", %{type: VintageNetDirect}},
    {"eth0", %{type: VintageNetEthernet, ipv4: %{method: :dhcp}}},
    {"wlan0", %{type: VintageNetWiFi}}
  ]

# Configure hardware pins (adjust for your target)
config :${appName},
  led_pin: 18,      # GPIO18
  button_pin: 17,   # GPIO17
  i2c_bus: "i2c-1",
  spi_bus: "spidev0.0"

# MDNs for device discovery
config :mdns_lite,
  services: [
    %{
      name: "${appName}",
      protocol: "http",
      transport: "tcp",
      port: 80
    }
  ]

# Platform-specific configuration
if Mix.target() == :rpi3 do
  config :${appName}, platform: :rpi3
  # Raspberry Pi 3 specific settings
end

if Mix.target() == :rpi4 do
  config :${appName}, platform: :rpi4
  # Raspberry Pi 4 specific settings
end

if Mix.target() == :bbb do
  config :${appName}, platform: :bbb
  # BeagleBone Black specific settings
end
`
      },
      {
        path: `config/dev.exs`,
        content: `import Config

# Development environment configuration

config :logger, :console,
  level: :debug,
  format: "$time $metadata[$level] $message\\n",
  metadata: [:request_id]

# Set higher stacktrace depth
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime
config :phoenix, :plug_init_mode, :runtime

# Enable code reloading for development
config :phoenix, :code_reloader, true
`
      },
      {
        path: `config/prod.exs`,
        content: `import Config

# Production environment configuration

config :logger, level: :info

# Configure NervesHub for OTA updates
config :nerves_hub_link,
  socket: [
    json_library: Jason,
    heartbeat_interval: 45_000
  ],
  ssl: [
    cert: System.get_env("NERVES_HUB_CERT"),
    key: System.get_env("NERVES_HUB_KEY")
  ]

# Reduce firmware size
config :phoenix, :gzip, true
config :phoenix, :trim_on_html_eex_engine, true
`
      },
      {
        path: `config/test.exs`,
        content: `import Config

# Test environment configuration

config :logger, level: :warn

# Configure hardware mocks for testing
config :${appName},
  mock_hardware: true,
  gpio_module: ${moduleName}.MockGPIO,
  i2c_module: ${moduleName}.MockI2C
`
      },
      {
        path: `rootfs_overlay/etc/iex.exs`,
        content: `# Add custom IEx configuration for on-device debugging

# Custom prompt
IEx.configure(
  default_prompt: "#{IO.ANSI.green()}iex(#{String.trim(Nerves.Runtime.KV.get("nerves_fw_product"))})>#{IO.ANSI.reset()} "
)

# Convenience aliases
import_file("/etc/iex_aliases.exs")
`
      },
      {
        path: `rootfs_overlay/etc/iex_aliases.exs`,
        content: `# Convenience aliases for device debugging

alias ${this.toPascalCase(this.getAppName(this.options))}.{
  DeviceRegistry,
  NetworkManager,
  FirmwareManager,
  Sensors,
  Devices
}

# Helper functions
defmodule H do
  def temp, do: Sensors.Temperature.get_current()
  def led_on, do: Devices.LEDController.on()
  def led_off, do: Devices.LEDController.off()
  def net, do: NetworkManager.get_status()
  def fw, do: FirmwareManager.get_status()
  def reboot, do: Nerves.Runtime.reboot()
end
`
      }
    ];
  }

  generateTestFiles(): { path: string; content: string }[] {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return [
      {
        path: `test/${appName}/hal/gpio_controller_test.exs`,
        content: `defmodule ${moduleName}.HAL.GPIOControllerTest do
  use ExUnit.Case
  alias ${moduleName}.HAL.GPIOController

  # These tests will only work on the host with mocked GPIO
  @moduletag :host_only

  describe "GPIO operations" do
    test "opens a pin for output" do
      assert {:ok, _ref} = GPIOController.open_pin(18, :output)
    end

    test "writes to an output pin" do
      {:ok, _ref} = GPIOController.open_pin(18, :output)
      assert :ok = GPIOController.write(18, 1)
      assert :ok = GPIOController.write(18, 0)
    end

    test "reads from an input pin" do
      {:ok, _ref} = GPIOController.open_pin(17, :input)
      assert {:ok, value} = GPIOController.read(17)
      assert value in [0, 1]
    end

    test "returns error for unopened pin" do
      assert {:error, :pin_not_open} = GPIOController.write(99, 1)
      assert {:error, :pin_not_open} = GPIOController.read(99)
    end
  end
end
`
      },
      {
        path: `test/${appName}/sensors/temperature_test.exs`,
        content: `defmodule ${moduleName}.Sensors.TemperatureTest do
  use ExUnit.Case
  alias ${moduleName}.Sensors.Temperature

  setup do
    # Ensure we're using mock sensor for tests
    Application.put_env(:${appName}, :sensor_type, :mock)
    :ok
  end

  describe "temperature readings" do
    test "returns current temperature reading" do
      # Give the sensor time to take a reading
      Process.sleep(1500)
      
      reading = Temperature.get_current()
      assert {timestamp, temp} = reading
      assert is_struct(timestamp, DateTime)
      assert is_float(temp)
      assert temp > 0 and temp < 50  # Reasonable temperature range
    end

    test "returns nil average with no readings" do
      # This would need a fresh sensor process
      assert Temperature.get_average(0) == nil
    end

    test "returns reading history" do
      Process.sleep(1500)
      
      history = Temperature.get_history()
      assert is_list(history)
      assert length(history) > 0
      
      {timestamp, temp} = hd(history)
      assert is_struct(timestamp, DateTime)
      assert is_float(temp)
    end
  end
end
`
      },
      {
        path: `test/${appName}/device_registry_test.exs`,
        content: `defmodule ${moduleName}.DeviceRegistryTest do
  use ExUnit.Case
  alias ${moduleName}.DeviceRegistry

  describe "device management" do
    test "registers a new device" do
      device_id = "test_sensor_1"
      assert :ok = DeviceRegistry.register_device(device_id, :sensor, %{type: :temperature})
      
      device = DeviceRegistry.get_device(device_id)
      assert device.id == device_id
      assert device.type == :sensor
      assert device.status == :active
    end

    test "lists devices by type" do
      DeviceRegistry.register_device("led_1", :led, %{pin: 18})
      DeviceRegistry.register_device("button_1", :button, %{pin: 17})
      DeviceRegistry.register_device("led_2", :led, %{pin: 19})
      
      leds = DeviceRegistry.list_devices(:led)
      assert length(leds) >= 2
      assert Enum.all?(leds, &(&1.type == :led))
    end

    test "unregisters a device" do
      device_id = "temp_device"
      DeviceRegistry.register_device(device_id, :sensor, %{})
      
      assert :ok = DeviceRegistry.unregister_device(device_id)
      assert DeviceRegistry.get_device(device_id) == nil
    end

    test "returns error when unregistering non-existent device" do
      assert {:error, :not_found} = DeviceRegistry.unregister_device("non_existent")
    end
  end
end
`
      }
    ];
  }

  async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    await super.generateFrameworkFiles(projectPath, options);

    // Generate Nerves-specific files
    const appName = this.getAppName(options);
    const moduleName = this.toPascalCase(appName);

    // Create firmware directory
    await fs.mkdir(path.join(projectPath, 'rootfs_overlay'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'rootfs_overlay', 'etc'), { recursive: true });

    // Generate Nerves-specific documentation
    await fs.writeFile(
      path.join(projectPath, 'docs', 'nerves-guide.md'),
      this.generateNervesGuide(options)
    );

    // Generate hardware abstraction layer structure
    await fs.mkdir(path.join(projectPath, 'lib', appName, 'hal'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'lib', appName, 'sensors'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'lib', appName, 'devices'), { recursive: true });

    // Generate HAL supervisor
    await fs.writeFile(
      path.join(projectPath, 'lib', appName, 'hal', 'supervisor.ex'),
      `defmodule ${moduleName}.HAL.Supervisor do
  @moduledoc """
  Supervisor for Hardware Abstraction Layer components.
  """
  use Supervisor

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    children = []
    Supervisor.init(children, strategy: :one_for_one)
  end
end
`
    );

    // Generate environment setup script
    await fs.writeFile(
      path.join(projectPath, 'scripts', 'setup_nerves.sh'),
      `#!/bin/bash
# Setup script for Nerves development

echo "Setting up Nerves development environment..."

# Install required system dependencies
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS
  brew install fwup squashfs coreutils xz pkg-config
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  # Linux
  sudo apt-get update
  sudo apt-get install -y build-essential automake autoconf git squashfs-tools ssh-askpass pkg-config
fi

# Install Nerves bootstrap
mix local.hex --force
mix local.rebar --force
mix archive.install hex nerves_bootstrap --force

echo "Nerves setup complete!"
echo ""
echo "To build firmware:"
echo "  export MIX_TARGET=rpi4  # or your target"
echo "  mix deps.get"
echo "  mix firmware"
echo ""
echo "To burn firmware to SD card:"
echo "  mix firmware.burn"
`,
      { mode: 0o755 }
    );
  }

  private generateNervesGuide(options: any): string {
    const appName = this.getAppName(options);

    return `# Nerves IoT Application Guide

## Overview

This is a Nerves-based IoT application for embedded Elixir development. Nerves provides a framework for building and deploying embedded software using Elixir.

## Supported Targets

- Raspberry Pi Zero: \`rpi0\`
- Raspberry Pi 3: \`rpi3\`, \`rpi3a\`
- Raspberry Pi 4: \`rpi4\`
- BeagleBone: \`bbb\` (BeagleBone Black/Green)
- Generic x86_64: \`x86_64\`

## Getting Started

### Development Setup

1. Install dependencies:
   \`\`\`bash
   ./scripts/setup_nerves.sh
   \`\`\`

2. Set your target:
   \`\`\`bash
   export MIX_TARGET=rpi4  # Change to your hardware
   \`\`\`

3. Get dependencies and build:
   \`\`\`bash
   mix deps.get
   mix firmware
   \`\`\`

### Burning Firmware

To SD card:
\`\`\`bash
mix firmware.burn
\`\`\`

Over the network (after initial burn):
\`\`\`bash
mix upload 192.168.1.100  # Device IP
\`\`\`

## Hardware Interfaces

### GPIO Control

Control LEDs and read buttons:

\`\`\`elixir
# In IEx on device
alias ${this.toPascalCase(appName)}.Devices.LEDController
LEDController.on()
LEDController.blink()
LEDController.pattern(:heartbeat)
\`\`\`

### Sensor Reading

Read sensor data:

\`\`\`elixir
alias ${this.toPascalCase(appName)}.Sensors.Temperature
Temperature.get_current()
Temperature.get_average(10)  # Last 10 minutes
\`\`\`

### Network Configuration

Configure WiFi:

\`\`\`elixir
alias ${this.toPascalCase(appName)}.NetworkManager
NetworkManager.configure_wifi("SSID", "password")
NetworkManager.get_status()
\`\`\`

## Firmware Updates

### Over-the-Air (OTA) Updates

1. Check for updates:
   \`\`\`elixir
   ${this.toPascalCase(appName)}.FirmwareManager.check_for_updates()
   \`\`\`

2. Apply update:
   \`\`\`elixir
   ${this.toPascalCase(appName)}.FirmwareManager.apply_update(url)
   \`\`\`

### NervesHub Integration

1. Register device with NervesHub
2. Configure certificates in \`config/prod.exs\`
3. Push firmware to NervesHub
4. Devices will auto-update based on policies

## Development Workflow

### On-Device Debugging

1. Connect via SSH:
   \`\`\`bash
   ssh ${appName}.local
   \`\`\`

2. Access IEx console:
   \`\`\`bash
   ssh ${appName}.local "iex"
   \`\`\`

### Custom Hardware

Add support for new hardware in:
- \`lib/${appName}/hal/\` - Hardware abstraction
- \`lib/${appName}/devices/\` - Device-specific logic
- \`lib/${appName}/sensors/\` - Sensor implementations

## Testing

Run tests on host:
\`\`\`bash
mix test
\`\`\`

Run tests for specific target:
\`\`\`bash
MIX_TARGET=rpi4 mix test
\`\`\`

## Production Deployment

1. Configure production settings in \`config/prod.exs\`
2. Set up NervesHub for OTA updates
3. Configure monitoring and telemetry
4. Build release firmware:
   \`\`\`bash
   MIX_ENV=prod mix firmware
   \`\`\`

## Troubleshooting

### Common Issues

1. **Firmware won't boot**: Check UART console output
2. **Network not working**: Verify VintageNet configuration
3. **GPIO errors**: Ensure correct pin numbers and permissions
4. **Sensor not reading**: Check I2C/SPI bus configuration

### Debug Commands

\`\`\`elixir
# System info
Nerves.Runtime.KV.get_all()

# Network debug
VintageNet.info()

# Reboot
Nerves.Runtime.reboot()
\`\`\`

## Resources

- [Nerves Documentation](https://hexdocs.pm/nerves)
- [Nerves Examples](https://github.com/nerves-project/nerves_examples)
- [VintageNet Cookbook](https://hexdocs.pm/vintage_net/cookbook.html)
`;
  }
}